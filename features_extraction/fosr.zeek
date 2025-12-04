@load base/protocols/conn

module FosR;

export {
    redef enum Log::ID += {LOG_TCP, LOG_UDP, LOG_TTL};

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
    };

    type InfoTTL : record {
        uid:
            string &log;
        ip:
            addr &log;
        ttl:
            int &log;
        proto:
            count &log;
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
global proto_int_list: table[string] of count;

event zeek_init() {
    Log::create_stream(LOG_UDP, [ $columns = InfoUDP, $path = "fosr_udp" ]);
    Log::create_stream(LOG_TCP, [ $columns = InfoTCP, $path = "fosr_tcp" ]);
    Log::create_stream(LOG_TTL, [ $columns = InfoTTL, $path = "fosr_ttl" ]);
}

# Extract TTL from the first packets sent in that connection
event new_packet(c : connection,
                 p : pkt_hdr) {
    if (!(c$uid in proto_int_list)) {
        proto_int_list[c$uid] = c$id$proto;
    }
    if (p?$ip) { # IPv4 packet
        local ttl = p$ip$ttl;
        if (p$ip$src == c$id$orig_h) { # forward packet
            if (!(c$uid in src_ttl_result)) {
                src_ttl_result[c$uid] = ttl;
            }
        } else if (p$ip$src == c$id$resp_h) { # backward packet
            local exists_dst = c$uid in dst_ttl_result;
            if (!exists_dst) {
                dst_ttl_result[c$uid] = ttl;
            }
        } else {
            print "Fatal error";
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
    if (c$uid in src_ttl_result) {
        local rec_src_ttl = InfoTTL(
            $uid = c$uid,
            $ip = c$id$orig_h,
            $ttl = src_ttl_result[c$uid],
            $proto = proto_int_list[c$uid]);
        Log::write(LOG_TTL, rec_src_ttl);
        delete src_ttl_result[c$uid];
    }
    if (c$uid in dst_ttl_result) {
        local rec_dst_ttl = InfoTTL(
            $uid = c$uid,
            $ip = c$id$resp_h,
            $ttl = dst_ttl_result[c$uid],
            $proto = proto_int_list[c$uid]);
        Log::write(LOG_TTL, rec_dst_ttl);
        delete dst_ttl_result[c$uid];
    }
    delete proto_int_list[c$uid];

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
