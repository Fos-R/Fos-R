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
        forward:
            vector of bool &log;
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
        forward:
            vector of bool &log;
    };
}

redef tcp_content_deliver_all_orig=T;
redef tcp_content_deliver_all_resp=T;
redef udp_content_deliver_all_orig=T;
redef udp_content_deliver_all_resp=T;

global iat_result_list : table[string] of vector of double;
global flags_result_list : table[string] of vector of string;
global forward_result_list : table[string] of vector of bool;
global payloads_result_list : table[string] of vector of string;
global last_time : table[string] of double;
global proto_list : table[string] of string;

event zeek_init() {
    Log::create_stream(LOG_UDP, [ $columns = InfoUDP, $path = "fosr_udp" ]);
    Log::create_stream(LOG_TCP, [ $columns = InfoTCP, $path = "fosr_tcp" ]);
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
            local rec_tcp = InfoTCP(
                $uid = c$uid,
                $payloads = payloads_result_list[c$uid],
                $flags = flags_result_list[c$uid],
                $iat = iat_result_list[c$uid],
                $forward = forward_result_list[c$uid],
                $conn_state = c$conn$conn_state);
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
                        $forward = forward_result_list[c$uid]);
            delete payloads_result_list[c$uid];
            delete iat_result_list[c$uid];
            delete forward_result_list[c$uid];
            Log::write(LOG_UDP, rec_udp);
        }
    }
}
