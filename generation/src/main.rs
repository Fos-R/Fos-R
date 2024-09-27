mod structs;
use structs::*;
mod tcp;
mod udp;
mod icmp;

mod stage1;
mod stage2;
mod stage3;

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

fn main() {
    // Init and import patterns and automata
    // let mut s1 = stage1::Stage1::new(42);
    // s1.import_patterns("patterns.json").expect("Cannot load patterns");
    let mut s2 = stage2::Stage2::new(42);
    let nb_automata = s2.import_automata_from_dir("../models/tas/");
    assert!(nb_automata > 0);
    let s3 = stage3::Stage3::new();

    let flows = vec![Flow::TCPFlow(FlowData {
    src_ip: Ipv4Addr::new(127, 0, 0, 1),
    dst_ip: Ipv4Addr::new(127, 0, 0, 2),
    src_port: 34200,
    dst_port: 8080,
    recorded_ttl_client: 23,
    recorded_ttl_server: 68,
    initial_ttl_client: 255,
    initial_ttl_server: 255,
    fwd_packets_count: 9,
    bwd_packets_count: 3,
    fwd_total_payload_length: 123,
    bwd_total_payload_length: 32,
    timestamp: Instant::now(),
    total_duration: Duration::new(5, 0)
    } )];

    let mut packets = vec![];
    // let flows = s1.generate_flows(100);
    for flow in flows.into_iter() {
        match flow {
            Flow::TCPFlow(flowdata) => {
                let headers = s2.generate_tcp_packets_info(flowdata);
                dbg!(&headers);
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
