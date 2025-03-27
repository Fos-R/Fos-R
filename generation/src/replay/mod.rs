use crate::structs::*;
use crate::utils::timeval_to_duration;
use pcap::{Capture, Offline};
use pnet_packet::Packet as PnetPacket;
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

pub mod config;

pub struct Replay {
    ip_replacement_map: HashMap<Ipv4Addr, Ipv4Addr>,
    file: String,
}

impl Replay {
    pub fn new(ip_replacement_map: HashMap<Ipv4Addr, Ipv4Addr>, file: String) -> Self {
        Replay {
            ip_replacement_map,
            file,
        }
    }

    pub fn parse_flows(&self) -> Vec<SeededData<Packets>> {
        let packets = self.read_file();
        let flows = self.split_flows(packets);

        flows
            .iter()
            .map(|(flow_id, packets)| self.to_seeded_packets(flow_id, packets))
            .collect()
    }

    fn read_file(&self) -> Vec<Packet> {
        let mut capture = Capture::<Offline>::from_file(&self.file).unwrap();
        let mut packets: Vec<Packet> = vec![];
        while let Ok(packet) = capture.next_packet() {
            let packet_: Packet = Packet {
                header: *packet.header,
                data: packet.data.to_vec(),
            };
            packets.push(packet_);
        }
        packets
    }

    fn split_flows(&self, packets: Vec<Packet>) -> HashMap<FlowId, Vec<Packet>> {
        let mut grouped_packets: HashMap<FlowId, Vec<Packet>> = HashMap::new();
        let mut non_remapped_ips: HashSet<Ipv4Addr> = HashSet::new();

        for mut packet in packets {
            let mut flow_id = FlowId::from_packet(&packet);
            flow_id.normalize();

            let src_ip = self
                .ip_replacement_map
                .get(&flow_id.src_ip)
                .unwrap_or_else(|| {
                    non_remapped_ips.insert(flow_id.src_ip);
                    &flow_id.src_ip
                });
            let dst_ip = self
                .ip_replacement_map
                .get(&flow_id.dst_ip)
                .unwrap_or_else(|| {
                    non_remapped_ips.insert(flow_id.dst_ip);
                    &flow_id.dst_ip
                });

            flow_id.src_ip = *src_ip;
            flow_id.dst_ip = *dst_ip;

            let ip_packet = packet.get_mutable_ip_packet();
            if let Some(mut ip_packet) = ip_packet {
                ip_packet.set_source(flow_id.src_ip);
                ip_packet.set_destination(flow_id.dst_ip);
            } else {
                println!("Malformed packet, skipping IP rewrite")
            }

            let flow = grouped_packets.entry(flow_id).or_insert(Vec::new());
            flow.push(packet);
        }

        log::warn!(
            "The following IPs were not remapped in the replay: {:#?}",
            non_remapped_ips
        );

        grouped_packets
    }

    fn to_seeded_packets(&self, flow_id: &FlowId, packets: &[Packet]) -> SeededData<Packets> {
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
                    fwd_packets_count: Some(fwd_packets_count),
                    bwd_packets_count: Some(bwd_packets_count),
                    timestamp: timeval_to_duration(packets[0].header.ts),
                }),
            },
            seed: 42,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Replay;
    use crate::stage3;
    use std::collections::HashMap;

    #[test]
    fn create_pcap() {
        let stage_replay = Replay::new(HashMap::new(), "original.pcap".to_string());
        let flows = stage_replay.parse_flows();
        for (i, seeded_data) in flows.iter().enumerate() {
            let flow_packets = seeded_data.data.packets.clone();
            stage3::pcap_export(flow_packets, format!("flow{}.pcap", i).as_str(), false).unwrap();
        }
    }
}
