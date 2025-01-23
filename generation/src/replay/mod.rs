#![allow(unused)]
use crate::stage4;
use crate::structs::*;
use crossbeam_channel::bounded;
use pcap::{Capture, Offline};
use pnet::packet::ipv4::Ipv4Packet;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::thread;

struct FlowId {
    src_pt: u16,
    dst_pt: u16,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    proto: Protocol,
}

fn from_pcap(infile: &str) -> Vec<SeededData<Packets>> {
    let mut capture = Capture::<Offline>::from_file(infile).unwrap();
    let flows: HashMap<FlowId, Vec<Packet>> = HashMap::new();
    while let Ok(packet) = capture.next_packet() {
        // println!("{:?}",packet);
        let ip_packet = Ipv4Packet::new(packet.data).expect("Replay only support IPv4 packets");
        println!("{:?}", ip_packet);
        // match ip_packet.get_next_level_protocol() {

        // };
        // TODO: recreate flows
    }
    vec![]
}

pub fn replay(infile: &str) {
    let mut threads = vec![];
    let (tx, rx) = bounded::<SeededData<Packets>>(crate::CHANNEL_SIZE);
    let builder = thread::Builder::new().name("Replay".into());
    let data = from_pcap(infile);
    threads.push(
        builder
            .spawn(move || {
                for flow in data.into_iter() {
                    tx.send(flow).unwrap();
                }
                log::trace!("S4 stops");
            })
            .unwrap(),
    );
    let proto = Protocol::TCP;
    let builder = thread::Builder::new().name(format!("Stage4-{:?}", proto));
    threads.push(
        builder
            .spawn(move || {
                log::trace!("Start S4");
                let s4 = stage4::Stage4::new(Ipv4Addr::new(127, 0, 0, 1), proto);
                while let Ok(packets) = rx.recv() {
                    s4.send(packets)
                }
                log::trace!("S4 stops");
            })
            .unwrap(),
    );
    for thread in threads {
        thread.join().unwrap();
    }
}
