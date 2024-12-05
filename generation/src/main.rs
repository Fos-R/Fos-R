mod structs;
use structs::*;
mod tcp;
mod udp;
mod icmp;

mod stage1;
mod stage2;
mod stage3;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn main() {
    // Init and import patterns and automata
    // let mut s1 = stage1::Stage1::new(42);
    // s1.import_patterns("../models/patterns.json").expect("Cannot load patterns");
    let mut s2 = stage2::Stage2::new(42);
    let nb_automata = s2.import_automata_from_dir("../models/tas/");
    assert!(nb_automata > 0);
    let s3 = stage3::Stage3::new(42);

    let mut packets = vec![];
    let mut ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    for _ in 0..10 {
        let headers = s2.generate_tcp_packets_info_no_flow(21, ts);
        packets.append(&mut s3.generate_tcp_packets(&headers));
        ts += Duration::from_millis(1000);
    }
    // export packets to pcap file
}
