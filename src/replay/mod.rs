use crate::structs::*;
use pcap_file::pcap::PcapReader;
use pnet_packet::{Packet as PnetPacket, ipv4};
use std::collections::HashMap;
use std::fs::File;
use std::net::Ipv4Addr;
use std::time::Instant;

// /// Parse the following TOML file
// /// [[ip_replacements]]
// /// old = "192.168.0.1"
// /// new = "192.168.56.101"
// /// [[ip_replacements]]
// /// old = "192.168.0.2"
// /// new = "192.168.56.102"
// ///
// /// into a HashMap<Ipv4Addr, Ipv4Addr>
// pub fn parse_config(config_str: &str) -> HashMap<Ipv4Addr, Ipv4Addr> {
//     let msg = "Ill-formed configuration file";
//     let table: HashMap<String, Vec<HashMap<String, String>>> =
//         toml::from_str(config_str).expect(msg);

//     table
//         .get("ip_replacements")
//         .expect(msg)
//         .iter()
//         .map(|entry| {
//             let old = entry.get("old").expect(msg).parse().expect(msg);
//             let new = entry.get("new").expect(msg).parse().expect(msg);
//             (old, new)
//         })
//         .collect::<HashMap<Ipv4Addr, Ipv4Addr>>()
// }

pub struct Replay {
    // ip_replacement_map: HashMap<Ipv4Addr, Ipv4Addr>,
    start_time: Instant,
}

impl Default for Replay {
    fn default() -> Self {
        Self::new()
    }
}

impl Replay {
    pub fn new() -> Self {
        Replay {
            start_time: Instant::now(),
        }
    }

    pub fn parse_flows(&self, file: &str) -> Vec<Packets> {
        let packets = self.read_file(file);
        let flows = self.split_flows(packets);

        flows
            .iter()
            .map(|(flow_id, packets)| self.to_packets(flow_id, packets))
            .collect()
    }

    fn read_file(&self, file: &str) -> Vec<Packet> {
        let file_in = File::open(file).expect("Error opening file");
        let mut pcap_reader = PcapReader::new(file_in).unwrap();
        let mut packets: Vec<Packet> = vec![];
        while let Some(packet) = pcap_reader.next_packet() {
            let packet = packet.unwrap();
            packets.push(Packet {
                timestamp: packet.timestamp,
                data: packet.data.to_vec(),
            });
        }
        packets
    }

    fn split_flows(&self, packets: Vec<Packet>) -> HashMap<FlowId, Vec<Packet>> {
        let mut grouped_packets: HashMap<FlowId, Vec<Packet>> = HashMap::new();

        for mut packet in packets {
            let mut flow_id = FlowId::from_packet(&packet);
            flow_id.normalize();

            // flow_id.src_ip = *self
            //     .ip_replacement_map
            //     .get(&flow_id.src_ip)
            //     .unwrap_or(&flow_id.src_ip);
            // flow_id.dst_ip = *self
            //     .ip_replacement_map
            //     .get(&flow_id.dst_ip)
            //     .unwrap_or(&flow_id.dst_ip);

            let ip_packet = packet.get_mutable_ip_packet();
            if let Some(mut ip_packet) = ip_packet {
                ip_packet.set_source(flow_id.src_ip);
                ip_packet.set_destination(flow_id.dst_ip);
                ip_packet.set_checksum(ipv4::checksum(&ip_packet.to_immutable()));
            } else {
                println!("Malformed packet, skipping IP rewrite")
            }

            let flow = grouped_packets.entry(flow_id).or_default();
            flow.push(packet);
        }

        grouped_packets
    }

    fn to_packets(&self, flow_id: &FlowId, packets: &[Packet]) -> Packets {
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

        let timestamps: Vec<_> = packets.iter().map(|p| p.timestamp).collect();

        let first_timestamp = timestamps[0];
        let first_instant = self.start_time - first_timestamp;
        let time_shift = self.start_time.duration_since(first_instant);

        Packets {
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
                timestamp: packets[0].timestamp - time_shift,
            }),
        }
    }
}

// TODO: passer en test d’intégration pour combiner avec génération
// #[cfg(test)]
// mod tests {
//     use super::Replay;
//     use crate::stage3;
//     use std::collections::HashMap;

//     #[test]
//     fn create_pcap() {
//         let stage_replay = Replay::new(HashMap::new(), "original.pcap".to_string());
//         let flows = stage_replay.parse_flows();
//         for (i, seeded_data) in flows.iter().enumerate() {
//             let flow_packets = seeded_data.packets.clone();
//             stage3::pcap_export(flow_packets, format!("flow{}.pcap", i).as_str(), false).unwrap();
//         }
//     }
// }
