@load base/protocols/conn

module FosR;

export {
    redef enum Log::ID += {LOG_TCP, LOG_UDP};

    type InfoTCP : record {
        uid:
            string &log;
        payloads:
            vector of string &log;
        iat:
            vector of double &log;
        forward_list:
            vector of bool &log;
        service:
            string &log &optional;
        src_ttl:
            int &log &optional;
        dst_ttl:
            int &log &optional;
        flags:
            vector of string &log;
        conn_state:
            string &log;
    };

    type InfoUDP : record {
        uid:
            string &log;
        payloads:
            vector of string &log;
        iat:
            vector of double &log;
        forward_list:
            vector of bool &log;
        service:
            string &log &optional;
        src_ttl:
            int &log &optional;
        dst_ttl:
            int &log &optional;
    };
}

redef tcp_content_deliver_all_orig=T;
redef tcp_content_deliver_all_resp=T;
redef udp_content_deliver_all_orig=T;
redef udp_content_deliver_all_resp=T;

global iat_result_list : table[string] of vector of double;
global src_ttl_result : table[string] of int;
global dst_ttl_result : table[string] of int;
global flags_result_list : table[string] of vector of string;
global forward_result_list : table[string] of vector of bool;
global payloads_result_list : table[string] of vector of string;
global last_time : table[string] of double;
global proto_list : table[string] of string;

event zeek_init() {
    Log::create_stream(LOG_UDP, [ $columns = InfoUDP, $path = "fosr_udp" ]);
    Log::create_stream(LOG_TCP, [ $columns = InfoTCP, $path = "fosr_tcp" ]);
}

# Get TTL
event new_packet(c : connection,
                 p : pkt_hdr) {
    if (p?$ip) { # IPv4 packet
        local ttl = p$ip$ttl;
        if (p$ip$src == c$id$orig_h) { # forward packet
            local exists_src = c$uid in src_ttl_result;
            if (!exists_src) {
                src_ttl_result[c$uid] = ttl;
            }
        } else { # backward packet
            local exists_dst = c$uid in dst_ttl_result;
            if (!exists_dst) {
                dst_ttl_result[c$uid] = ttl;
            }
        }
    }
}

# For each TCP packet, log its direction, flags, payload and IAT
event tcp_packet(c : connection,
                 is_orig : bool,
                 flags : string,
                 seq : count,
                 ack : count,
                 len : count,
                 payload : string) {
    local exists = c$uid in proto_list;
    if (!exists) {
        flags_result_list[c$uid] = vector();
        iat_result_list[c$uid] = vector();
        forward_result_list[c$uid] = vector();
        payloads_result_list[c$uid] = vector();
        proto_list[c$uid] = "tcp";
    }
    flags_result_list[c$uid][| flags_result_list[c$uid] |] = flags;
    forward_result_list[c$uid][| forward_result_list[c$uid] |] = is_orig;
    payloads_result_list[c$uid][| payloads_result_list[c$uid] |] =
        encode_base64(payload);
    if (!exists) {
        iat_result_list[c$uid][| iat_result_list[c$uid] |] = 0;
    } else {
        local iat = time_to_double(network_time()) - last_time[c$uid];
        if (iat < 0) {
            print "Negative IAT!";
            iat_result_list[c$uid][| iat_result_list[c$uid] |] = 0;
        } else {
            iat_result_list[c$uid][| iat_result_list[c$uid] |] = iat;
        }
    }
    last_time[c$uid] = time_to_double(network_time());
}

# For each UDP packet, log its direction, payload and IAT
event udp_contents(c : connection, is_orig : bool, contents : string) {
    local exists = c$uid in proto_list;
    if (!exists) {
        iat_result_list[c$uid] = vector();
        forward_result_list[c$uid] = vector();
        payloads_result_list[c$uid] = vector();
        proto_list[c$uid] = "udp";
    }
    forward_result_list[c$uid][| forward_result_list[c$uid] |] = is_orig;
    payloads_result_list[c$uid][| payloads_result_list[c$uid] |] =
        encode_base64(contents);
    if (!exists) {
        iat_result_list[c$uid][| iat_result_list[c$uid] |] = 0;
    } else {
        local iat = time_to_double(network_time()) - last_time[c$uid];
        if (iat < 0) {
            print "Negative IAT!";
            iat_result_list[c$uid][| iat_result_list[c$uid] |] = 0;
        } else {
            iat_result_list[c$uid][| iat_result_list[c$uid] |] = iat;
        }
    }
    last_time[c$uid] = time_to_double(network_time());
}

# At the connection closure, save the connection data
event connection_state_remove(c : connection) {
    if (c$uid in proto_list) {
        if (proto_list[c$uid] == "tcp") {
            local conn_state_category: string;
            if (c$conn$conn_state == "SF") {
                conn_state_category = "SF";
            } else if (c$conn$conn_state == "SH") {
                conn_state_category = "SH";
            } else if (c$conn$conn_state == "RSTR" || c$conn$conn_state == "RSTO" || c$conn$conn_state == "RSTOS0" || c$conn$conn_state == "RSTRH") {
                conn_state_category = "RST";
            } else if (c$conn$conn_state == "S0") {
                conn_state_category = "S0";
            } else if (c$conn$conn_state == "REJ") {
                conn_state_category = "REJ";
            } else {
                conn_state_category = "other";
            }

            local rec_tcp = InfoTCP(
                $uid = c$uid,
                $payloads = payloads_result_list[c$uid],
                $flags = flags_result_list[c$uid],
                $iat = iat_result_list[c$uid],
                $forward_list = forward_result_list[c$uid],
                $conn_state = conn_state_category);
            if (c$uid in src_ttl_result) {
                rec_tcp$src_ttl = src_ttl_result[c$uid];
            }
            if (c$uid in dst_ttl_result) {
                rec_tcp$dst_ttl = dst_ttl_result[c$uid];
            }
            if (c$conn?$service) {
                rec_tcp$service = c$conn$service;
            }

            delete flags_result_list[c$uid];
            delete payloads_result_list[c$uid];
            delete iat_result_list[c$uid];
            delete forward_result_list[c$uid];
            Log::write(LOG_TCP, rec_tcp);
        } else if (proto_list[c$uid] == "udp") {
            local rec_udp =
                InfoUDP($uid = c$uid,
                        $payloads = payloads_result_list[c$uid],
                        $iat = iat_result_list[c$uid],
                        $forward_list = forward_result_list[c$uid]);
            if (c$uid in src_ttl_result) {
                rec_udp$src_ttl = src_ttl_result[c$uid];
            }
            if (c$uid in dst_ttl_result) {
                rec_udp$dst_ttl = dst_ttl_result[c$uid];
            }
            if (c$conn?$service) {
                rec_udp$service = c$conn$service;
            }

            delete payloads_result_list[c$uid];
            delete iat_result_list[c$uid];
            delete forward_result_list[c$uid];
            Log::write(LOG_UDP, rec_udp);
        }
    }
}
