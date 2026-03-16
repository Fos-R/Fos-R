@load base/protocols/conn

module FosR;

export {
    redef enum Log::ID += {LOG_TCP, LOG_UDP, LOG_ICMP};

    type InfoTCP : record {
        ts:
            time &log;
        uid:
            string &log;
        payloads:
            vector of string &log;
        iat:
            vector of double &log;
        forward_list:
            vector of bool &log;
        orig_l2_addr:
            string &log;
        resp_l2_addr:
            string &log &optional;
        orig_ttl:
            int &log;
        resp_ttl:
            int &log &optional;
        service:
            string &log &optional;
        flags:
            vector of string &log;
        conn_state:
            string &log;
    };

    type InfoUDP : record {
        ts:
            time &log;
        uid:
            string &log;
        payloads:
            vector of string &log;
        iat:
            vector of double &log;
        forward_list:
            vector of bool &log;
        orig_l2_addr:
            string &log;
        resp_l2_addr:
            string &log &optional;
        orig_ttl:
            int &log;
        resp_ttl:
            int &log &optional;
        service:
            string &log &optional;
    };

    type InfoICMP : record {
        ts:
            time &log;
        uid:
            string &log;
        types:
            vector of count &log;
        codes:
            vector of count &log;
        iat:
            vector of double &log;
        forward_list:
            vector of bool &log;
        orig_l2_addr:
            string &log &optional;
        resp_l2_addr:
            string &log &optional;
        orig_ttl:
            int &log;
        resp_ttl:
            int &log &optional;
    };

}

redef tcp_content_deliver_all_orig=T;
redef tcp_content_deliver_all_resp=T;
redef udp_content_deliver_all_orig=T;
redef udp_content_deliver_all_resp=T;

# Only keep the first 1000 packets
const max_packet_number = 1000;

global iat_result_list : table[string] of vector of double;
global src_ttl_result : table[string] of int;
global dst_ttl_result : table[string] of int;
global orig_mac : table[string] of string;
global resp_mac : table[string] of string;

global flags_result_list : table[string] of vector of string;
global forward_result_list : table[string] of vector of bool;
global payloads_result_list : table[string] of vector of string;
global last_time : table[string] of double;
global first_time : table[string] of time;
global proto_list : table[string] of string;
global icmp_type_list : table[string] of vector of count;
global icmp_code_list : table[string] of vector of count;
global icmp_origin_list : table[string] of addr;

event zeek_init() {
    Log::create_stream(LOG_UDP, [ $columns = InfoUDP, $path = "fosr_udp" ]);
    Log::create_stream(LOG_TCP, [ $columns = InfoTCP, $path = "fosr_tcp" ]);
    Log::create_stream(LOG_ICMP, [ $columns = InfoICMP, $path = "fosr_icmp" ]);
}

# Extract TTL from the first packets sent in that connection
event new_packet(c : connection,
                 p : pkt_hdr) {
    if (p?$ip) { # IPv4 packet
        local ttl = p$ip$ttl;
        if (p$ip$src == c$id$orig_h) { # forward packet
            if (!(c$uid in src_ttl_result)) {
                src_ttl_result[c$uid] = ttl;
            }
        } else if (p$ip$src == c$id$resp_h) { # backward packet
            if (!(c$uid in dst_ttl_result)) {
                dst_ttl_result[c$uid] = ttl;
            }
        } else {
            print "Fatal error";
        }
    }

# ICMP: cette approche ne convient pas. Il faut regarder paquet par paquet pour obtenir les bons types et codes.
# https://docs.zeek.org/en/master/scripts/base/init-bare.zeek.html#type-pkt_hdr

    if (c$id$proto == 1) { # ICMP
        local exists = c$uid in proto_list;
        if (!exists) {
            icmp_origin_list[c$uid] = c$id$orig_h;
            first_time[c$uid] = network_time();
            iat_result_list[c$uid] = vector();
            icmp_type_list[c$uid] = vector();
            icmp_code_list[c$uid] = vector();
            forward_result_list[c$uid] = vector();
            proto_list[c$uid] = "icmp";
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

        forward_result_list[c$uid][| forward_result_list[c$uid] |] = c$id$orig_h == icmp_origin_list[c$uid];
        icmp_type_list[c$uid][| icmp_type_list[c$uid] |] = port_to_count(c$id$orig_p);
        icmp_code_list[c$uid][| icmp_code_list[c$uid] |] = port_to_count(c$id$resp_p);
        last_time[c$uid] = time_to_double(network_time());
    }
}

event connection_state_remove(c: connection) {
    if (c$orig?$l2_addr) {
        orig_mac[c$uid] = c$orig$l2_addr;
    }
    if (c$resp?$l2_addr) {
        resp_mac[c$uid] = c$resp$l2_addr;
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
    if (is_v4_addr(c$id$orig_h)) { # IPv4 only
        local exists = c$uid in proto_list;
        if (!exists) {
            first_time[c$uid] = network_time();
            flags_result_list[c$uid] = vector();
            iat_result_list[c$uid] = vector();
            forward_result_list[c$uid] = vector();
            payloads_result_list[c$uid] = vector();
            proto_list[c$uid] = "tcp";
        }
        if (|flags_result_list[c$uid]| < max_packet_number) {
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
        }
        last_time[c$uid] = time_to_double(network_time());
    }
}

# For each UDP packet, log its direction, payload and IAT
event udp_contents(c : connection, is_orig : bool, contents : string) {
    if (is_v4_addr(c$id$orig_h)) { # IPv4 only
        local exists = c$uid in proto_list;
        if (!exists) {
            first_time[c$uid] = network_time();
            iat_result_list[c$uid] = vector();
            forward_result_list[c$uid] = vector();
            payloads_result_list[c$uid] = vector();
            proto_list[c$uid] = "udp";
        }
        if (|forward_result_list[c$uid]| < max_packet_number) {
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
        }
        last_time[c$uid] = time_to_double(network_time());
    }
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

            if (c$uid in src_ttl_result) { # incomplete flows may miss it
                local rec_tcp = InfoTCP(
                    $ts = first_time[c$uid],
                    $uid = c$uid,
                    $payloads = payloads_result_list[c$uid],
                    $flags = flags_result_list[c$uid],
                    $iat = iat_result_list[c$uid],
                    $forward_list = forward_result_list[c$uid],
                    $orig_ttl = src_ttl_result[c$uid],
                    $orig_l2_addr = orig_mac[c$uid],
                    $resp_l2_addr = resp_mac[c$uid],
                    $conn_state = conn_state_category);
                if (c$uid in dst_ttl_result) {
                    rec_tcp$resp_ttl = dst_ttl_result[c$uid];
                }
                if (c$conn?$service) {
                    rec_tcp$service = c$conn$service + ":" + cat(c$id$resp_p);
                } else {
                    rec_tcp$service = cat(c$id$resp_p);
                }
                Log::write(LOG_TCP, rec_tcp);
            }

            delete orig_mac[c$uid];
            delete resp_mac[c$uid];
            delete dst_ttl_result[c$uid];
            delete src_ttl_result[c$uid];
            delete first_time[c$uid];
            delete flags_result_list[c$uid];
            delete payloads_result_list[c$uid];
            delete iat_result_list[c$uid];
            delete forward_result_list[c$uid];
        } else if (proto_list[c$uid] == "udp") {
            if (c$uid in src_ttl_result) { # incomplete flows may miss it
                local rec_udp =
                    InfoUDP($ts = first_time[c$uid],
                            $uid = c$uid,
                            $payloads = payloads_result_list[c$uid],
                            $iat = iat_result_list[c$uid],
                            $forward_list = forward_result_list[c$uid],
                            $orig_l2_addr = orig_mac[c$uid],
                            $resp_l2_addr = resp_mac[c$uid],
                            $orig_ttl = src_ttl_result[c$uid]);
                if (c$uid in dst_ttl_result) {
                    rec_udp$resp_ttl = dst_ttl_result[c$uid];
                }
                if (c$conn?$service) {
                    rec_udp$service = c$conn$service + ":" + cat(c$id$resp_p);
                } else {
                    rec_udp$service = cat(c$id$resp_p);
                }
                Log::write(LOG_UDP, rec_udp);
            }

            delete orig_mac[c$uid];
            delete resp_mac[c$uid];
            delete dst_ttl_result[c$uid];
            delete src_ttl_result[c$uid];
            delete first_time[c$uid];
            delete payloads_result_list[c$uid];
            delete iat_result_list[c$uid];
            delete forward_result_list[c$uid];
        } else if (proto_list[c$uid] == "icmp") {
            if (c$uid in src_ttl_result) { # incomplete flows may miss it
                local rec_icmp =
                    InfoICMP($ts = first_time[c$uid],
                            $uid = c$uid,
                            $types = icmp_type_list[c$uid],
                            $codes = icmp_code_list[c$uid],
                            $iat = iat_result_list[c$uid],
                            $forward_list = forward_result_list[c$uid],
                            $orig_l2_addr = orig_mac[c$uid],
                            $resp_l2_addr = resp_mac[c$uid],
                            $orig_ttl = src_ttl_result[c$uid]);
                if (c$uid in dst_ttl_result) {
                    rec_icmp$resp_ttl = dst_ttl_result[c$uid];
                }
            Log::write(LOG_ICMP, rec_icmp);
            }

            delete orig_mac[c$uid];
            delete resp_mac[c$uid];
            delete dst_ttl_result[c$uid];
            delete src_ttl_result[c$uid];
            delete first_time[c$uid];
            delete payloads_result_list[c$uid];
            delete iat_result_list[c$uid];
            delete forward_result_list[c$uid];
            delete icmp_type_list[c$uid];
            delete icmp_code_list[c$uid];
            delete icmp_origin_list[c$uid];
        }
    }
}
