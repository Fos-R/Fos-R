@load base/protocols/conn

module FosR;

export {
    redef enum Log::ID += {LOG_TCP, LOG_UDP, LOG_ICMP, LOG_TTL};

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
        service:
            string &log &optional;
        flags:
            vector of string &log;
        conn_state:
            string &log;
    };

# TODO: passer TTL dans InfoUDP, InfoICMP et InfoTCP

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
    };

    type InfoTTL : record {
        uid:
            string &log;
        ip:
            addr &log;
        ttl:
            int &log;
#        mac_addr:
#            string &log;
        proto:
            count &log;
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
#global mac_result : table[addr] of string;

global flags_result_list : table[string] of vector of string;
global forward_result_list : table[string] of vector of bool;
global payloads_result_list : table[string] of vector of string;
global last_time : table[string] of double;
global first_time : table[string] of time;
global proto_list : table[string] of string;
global proto_int_list: table[string] of count;
global icmp_type_list : table[string] of vector of count;
global icmp_code_list : table[string] of vector of count;
global icmp_origin_list : table[string] of addr;

event zeek_init() {
    Log::create_stream(LOG_UDP, [ $columns = InfoUDP, $path = "fosr_udp" ]);
    Log::create_stream(LOG_TCP, [ $columns = InfoTCP, $path = "fosr_tcp" ]);
    Log::create_stream(LOG_ICMP, [ $columns = InfoICMP, $path = "fosr_icmp" ]);
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

#event connection_state_remove(c: connection) &priority=-10 {
#    print c$orig;
#    print c$resp;
#    if (!(c$id$orig_h in mac_result) && c$orig?$l2_addr) {
#        print "OK 1";
#        mac_result[c$id$orig_h] = c$orig$l2_addr;
#    }
#    if (!(c$id$resp_h in mac_result) && c$resp?$l2_addr) {
#        print "OK 2";
#        mac_result[c$id$resp_h] = c$resp$l2_addr;
#    }
#}


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

# For each UDP packet, log its direction, payload and IAT
event udp_contents(c : connection, is_orig : bool, contents : string) {
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

# At the connection closure, save the connection data
event connection_state_remove(c : connection) {
    if (c$uid in src_ttl_result) {
        local rec_src_ttl = InfoTTL(
            $uid = c$uid,
            $ip = c$id$orig_h,
            $ttl = src_ttl_result[c$uid],
#            $mac_addr = mac_result[c$id$orig_h],
            $proto = proto_int_list[c$uid]);
        Log::write(LOG_TTL, rec_src_ttl);
        delete src_ttl_result[c$uid];
#        delete mac_result[c$id$orig_h];
    }
    if (c$uid in dst_ttl_result) {
        local rec_dst_ttl = InfoTTL(
            $uid = c$uid,
            $ip = c$id$resp_h,
            $ttl = dst_ttl_result[c$uid],
#            $mac_addr = mac_result[c$id$resp_h],
            $proto = proto_int_list[c$uid]);
        Log::write(LOG_TTL, rec_dst_ttl);
        delete dst_ttl_result[c$uid];
#        delete mac_result[c$id$resp_h];
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
                $ts = first_time[c$uid],
                $uid = c$uid,
                $payloads = payloads_result_list[c$uid],
                $flags = flags_result_list[c$uid],
                $iat = iat_result_list[c$uid],
                $forward_list = forward_result_list[c$uid],
                $conn_state = conn_state_category);
            if (c$conn?$service) {
                rec_tcp$service = c$conn$service + ":" + cat(c$id$resp_p);
            } else {
                rec_tcp$service = cat(c$id$resp_p);
            }

            delete first_time[c$uid];
            delete flags_result_list[c$uid];
            delete payloads_result_list[c$uid];
            delete iat_result_list[c$uid];
            delete forward_result_list[c$uid];
            Log::write(LOG_TCP, rec_tcp);
        } else if (proto_list[c$uid] == "udp") {
            local rec_udp =
                InfoUDP($ts = first_time[c$uid],
                        $uid = c$uid,
                        $payloads = payloads_result_list[c$uid],
                        $iat = iat_result_list[c$uid],
                        $forward_list = forward_result_list[c$uid]);
            if (c$conn?$service) {
                rec_udp$service = c$conn$service + ":" + cat(c$id$resp_p);
            } else {
                rec_udp$service = cat(c$id$resp_p);
            }

            delete first_time[c$uid];
            delete payloads_result_list[c$uid];
            delete iat_result_list[c$uid];
            delete forward_result_list[c$uid];
            Log::write(LOG_UDP, rec_udp);
        } else if (proto_list[c$uid] == "icmp") {
            local rec_icmp =
                InfoICMP($ts = first_time[c$uid],
                        $uid = c$uid,
                        $types = icmp_type_list[c$uid],
                        $codes = icmp_code_list[c$uid],
                        $iat = iat_result_list[c$uid],
                        $forward_list = forward_result_list[c$uid]);

            delete first_time[c$uid];
            delete payloads_result_list[c$uid];
            delete iat_result_list[c$uid];
            delete forward_result_list[c$uid];
            delete icmp_type_list[c$uid];
            delete icmp_code_list[c$uid];
            delete icmp_origin_list[c$uid];
            Log::write(LOG_ICMP, rec_icmp);
        }
    }
}
