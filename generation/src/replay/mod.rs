#![allow(unused)]
use crate::stage4;
use crate::stage4::FlowId;
use crate::structs::*;
use crossbeam_channel::bounded;
use pcap::{Capture, Offline};
use pnet::packet::ipv4::Ipv4Packet;
use pnet_packet::Packet as PnetPacket;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::thread;
use std::time::Instant;

const ETHERNET_HEADER_SIZE: usize = 14;
const IPV4_SRC_OFFSET: usize = ETHERNET_HEADER_SIZE + 12;
const IPV4_DST_OFFSET: usize = ETHERNET_HEADER_SIZE + 16;

pub struct Replay {
    source_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
    start_time: Instant,
}

fn get_flows(packets: Vec<Packet>) -> Vec<SeededData<Packets>> {
    let mut flows: Vec<SeededData<Packets>> = Vec::new();

    let mut current_flow_id_opt: Option<FlowId> = None;
    let mut current_flow_packets: Vec<Packet> = Vec::new();

    for packet in packets {
        let flow_id = extract_flow_id(&packet);

        match current_flow_id_opt {
            None => {
                current_flow_id_opt = Some(flow_id);
            }
            Some(ref current_flow_id) => {
                if *current_flow_id != flow_id {
                    flows.push(to_full_flow(&current_flow_id, &current_flow_packets));
                    current_flow_packets.clear();
                    current_flow_id_opt = Some(flow_id);
                }
            }
        }
        current_flow_packets.push(packet);
    }

    if let Some(current_flow_id) = &current_flow_id_opt {
        if !current_flow_packets.is_empty() {
            flows.push(to_full_flow(current_flow_id, &current_flow_packets));
        }
    }

    flows
}

fn to_full_flow(flow_id: &FlowId, packets: &[Packet]) -> SeededData<Packets> {
    let directions: Vec<PacketDirection> = packets
        .iter()
        .map(|p| {
            let eth_packet = pnet_packet::ethernet::EthernetPacket::new(&p.data).unwrap();
            let ip_packet = pnet_packet::ipv4::Ipv4Packet::new(eth_packet.payload()).unwrap();

            if ip_packet.get_source() == flow_id.src_ip {
                PacketDirection::Forward
            } else {
                PacketDirection::Backward
            }
        })
        .collect();

    let fwd_packets_count = directions
        .iter()
        .filter(|&&d| d == PacketDirection::Forward)
        .count();
    let bwd_packets_count = directions
        .iter()
        .filter(|&&d| d == PacketDirection::Backward)
        .count();

    let timestamps = packets
        .iter()
        .map(|p| p.header.ts)
        .map(timeval_to_duration)
        .collect();

    SeededData {
        data: Packets {
            packets: packets.into(),
            directions,
            timestamps,
            flow: Flow::TCP(FlowData {
                src_ip: flow_id.src_ip,
                dst_ip: flow_id.dst_ip,
                src_port: flow_id.src_port,
                dst_port: flow_id.dst_port,
                ttl_client: 64,
                ttl_server: 64,
                fwd_packets_count,
                bwd_packets_count,
                timestamp: timeval_to_duration(packets[0].header.ts),
            }),
        },
        seed: 42,
    }
}

fn extract_flow_id(packet: &Packet) -> FlowId {
    let eth_packet = pnet_packet::ethernet::EthernetPacket::new(&packet.data).unwrap();
    let ip_packet = pnet_packet::ipv4::Ipv4Packet::new(eth_packet.payload()).unwrap();
    let tcp_packet = pnet_packet::tcp::TcpPacket::new(ip_packet.payload()).unwrap();

    FlowId {
        src_ip: ip_packet.get_source(),
        dst_ip: ip_packet.get_destination(),
        src_port: tcp_packet.get_source(),
        dst_port: tcp_packet.get_destination(),
    }
}

impl Replay {
    pub fn new() -> Self {
        let source_ip = Ipv4Addr::new(127, 0, 0, 1);
        let dest_ip = Ipv4Addr::new(127, 0, 0, 2);
        let start_time = Instant::now();
        Replay {
            source_ip,
            dest_ip,
            start_time,
        }
    }

    pub fn from_pcap(infile: &str) -> Vec<SeededData<Packets>> {
        let mut capture = Capture::<Offline>::from_file(infile).unwrap();
        let flows: HashMap<FlowId, Vec<Packet>> = HashMap::new();
        let mut packets: Vec<Packet> = vec![];
        while let Ok(packet) = capture.next_packet() {
            let packet_: Packet = Packet {
                header: *packet.header,
                data: packet.data.to_vec(),
            };
            if packet_.data.len() >= IPV4_DST_OFFSET + 4 {
                let src_octets = self.source_ip.octets();
                let dst_octets = self.dest_ip.octets();
                packet_.data[IPV4_SRC_OFFSET..IPV4_SRC_OFFSET + 4].copy_from_slice(&src_octets);
                packet_.data[IPV4_DST_OFFSET..IPV4_DST_OFFSET + 4].copy_from_slice(&dst_octets);
            } else {
                println!("Packet too short, skipping IP rewrite: len = {}", packet_.data.len());
            }        packets.push(packet_);
        }
        get_flows(packets)
    }
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
    // let proto = Protocol::TCP;
    // let builder = thread::Builder::new().name(format!("Stage4-{:?}", proto));
    // threads.push(
    //     builder
    //         .spawn(move || {
    //             log::trace!("Start S4");
    //             let s4 = stage4::Stage4::new(Ipv4Addr::new(127, 0, 0, 1), proto);
    //             while let Ok(packets) = rx.recv() {
    //                 s4.send(packets)
    //             }
    //             log::trace!("S4 stops");
    //         })
    //         .unwrap(),
    // );
    for thread in threads {
        thread.join().unwrap();
    }
}
