use crate::structs::*;
use crate::utils::timeval_to_duration;
use pcap::{Capture, Offline};
use pnet_packet::Packet as PnetPacket;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Instant;

const ETHERNET_HEADER_SIZE: usize = 14;
const IPV4_SRC_OFFSET: usize = ETHERNET_HEADER_SIZE + 12;
const IPV4_DST_OFFSET: usize = ETHERNET_HEADER_SIZE + 16;

pub struct Replay {
    source_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
    file: String,
    rewrite: Option<String>,
    start_time: Instant,
}

fn get_flows(packets: Vec<Packet>) -> Vec<SeededData<Packets>> {
    let mut grouped_packets: HashMap<FlowId, Vec<Packet>> = HashMap::new();

    for packet in packets {
        let flow_id = FlowId::from_packet(&packet);

        let flow = grouped_packets.entry(flow_id).or_insert(Vec::new());
        flow.push(packet);
    }

    grouped_packets
        .iter()
        .map(|(flow_id, packets)| to_full_flow(flow_id, packets))
        .collect()
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

impl Replay {
    pub fn new(source_ip: Ipv4Addr, dest_ip: Ipv4Addr, file: String, rewrite: Option<String>) -> Self {
        let start_time = Instant::now();
        Replay {
            source_ip,
            dest_ip,
            start_time,
            file,
            rewrite,
        }
    }

    pub fn extract_flows(&self) -> Vec<SeededData<Packets>> {
        let mut capture = Capture::<Offline>::from_file(&self.file).unwrap();
        let mut packets: Vec<Packet> = vec![];
        while let Ok(packet) = capture.next_packet() {
            let mut packet_: Packet = Packet {
                header: *packet.header,
                data: packet.data.to_vec(),
            };
            if packet_.data.len() >= IPV4_DST_OFFSET + 4 {
                let src_octets = self.source_ip.octets();
                let dst_octets = self.dest_ip.octets();
                packet_.data[IPV4_SRC_OFFSET..IPV4_SRC_OFFSET + 4].copy_from_slice(&src_octets);
                packet_.data[IPV4_DST_OFFSET..IPV4_DST_OFFSET + 4].copy_from_slice(&dst_octets);
            } else {
                println!(
                    "Packet too short, skipping IP rewrite: len = {}",
                    packet_.data.len()
                );
            }
            packets.push(packet_);
        }
        get_flows(packets)
    }
}
