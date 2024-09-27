mod structs;
use structs::*;

mod stage1;
mod stage2;
mod stage3;

fn main() {
    // Init and import patterns and automata
    let mut s1 = stage1::Stage1::new();
    // s1.import_patterns("patterns.json");
    let mut s2 = stage2::Stage2::new(42);
    s2.import_automata_from_dir("../models/tas/");
    let s3 = stage3::Stage3::new();

    let mut packets = vec![];
    let flows = s1.generate_flows(100);
    for flow in flows.into_iter() {
        match flow {
            Flow::TCPFlow(flowdata) => {
                let headers = s2.generate_tcp_packets_info(flowdata);
                packets.append(&mut s3.generate_tcp_packets(&headers));
            },
            Flow::UDPFlow(flowdata) => {
                let headers = s2.generate_udp_packets_info(flowdata);
                packets.append(&mut s3.generate_udp_packets(&headers));
            },
            Flow::ICMPFlow(flowdata) => {
                let headers = s2.generate_icmp_packets_info(flowdata);
                packets.append(&mut s3.generate_icmp_packets(&headers));
            },
        }
    }

    // export packets to pcap file
}
