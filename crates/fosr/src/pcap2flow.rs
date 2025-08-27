use crate::structs::*;
use pcap_file::pcap::PcapReader;
use std::collections::HashMap;
use std::fs::File;
use std::time::Duration;
use std::net::Ipv4Addr;
use std::io::BufReader;
use pnet_packet::ethernet;
use pnet_packet::ipv4;
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::tcp;
use pnet_packet::udp;
use pnet_packet::Packet;
use pcap_file::pcap;

const DURATION_THRESHOLD: Duration = Duration::from_secs(60);

// timestamp,duration,protocol,src_ip,dst_ip,dst_port,fwd_packets,bwd_packets,fwd_bytes,bwd_bytes,time_sequence,payloads

#[derive(Debug)]
pub struct FlowStats {
    pub timestamp: Duration,
    pub duration: Duration,
    pub protocol: Protocol,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub ttl_client: u8,
    pub ttl_server: u8,
    pub fwd_packets_count: usize,
    pub bwd_packets_count: usize,
    pub fwd_bytes: usize,
    pub bwd_bytes: usize,
    pub payloads: Vec<u8>,
    pub directions: Vec<PacketDirection>,
    pub flags: Vec<u8>,
    pub iat: Vec<Duration>,
}

enum PacketInfo {
    TCP(TCPPacketInfo),
    UDP(UDPPacketInfo),
    ICMP(ICMPPacketInfo),
}

#[derive(Debug)]
struct TCPPacketInfo {
    payload: Vec<u8>,
    ts: Duration,
    flags: u8,
    src_ip: Ipv4Addr,
}

#[derive(Debug)]
struct ICMPPacketInfo {
    // we assume no payload
    // we may need to add more fields to correctly generate them
    ts: Duration,
    src_ip: Ipv4Addr,
}

#[derive(Debug)]
struct UDPPacketInfo {
    payload: Vec<u8>,
    ts: Duration,
    src_ip: Ipv4Addr,
}

impl From<pcap::PcapPacket<'_>> for PacketInfo {

    fn from(p: pcap::PcapPacket<'_>) -> PacketInfo {
        let eth_packet = ethernet::EthernetPacket::new(&p.data).unwrap();
        let ip_packet = ipv4::Ipv4Packet::new(eth_packet.payload()).unwrap();

        match ip_packet.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp => {
                let tcp_packet = tcp::TcpPacket::new(ip_packet.payload()).unwrap();
                PacketInfo::TCP(TCPPacketInfo {
                    payload: tcp_packet.payload().to_vec(),
                    ts: p.timestamp,
                    flags: tcp_packet.get_flags(),
                    src_ip: ip_packet.get_source(),
                } )
            }
            IpNextHeaderProtocols::Udp => {
                let udp_packet = udp::UdpPacket::new(ip_packet.payload()).unwrap();
                PacketInfo::UDP(UDPPacketInfo {
                    payload: udp_packet.payload().to_vec(),
                    ts: p.timestamp,
                    src_ip: ip_packet.get_source(),
                } )
            }
            _ => panic!("Unsupported protocol"),
        }
    }

}

impl FlowStats {

    fn new_from_tcp(flow_id: FlowId, packets: Vec<TCPPacketInfo>) -> Self {
        let first_packet = packets.first().unwrap(); // we know there is a least one packet

        let directions: Vec<PacketDirection> = packets
            .iter()
            .map(|p| if p.src_ip == flow_id.src_ip { 
                    PacketDirection::Forward }
                    else {
                    PacketDirection::Backward
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


        FlowStats {
            timestamp: first_packet.ts,
            duration: packets.last().unwrap().ts - first_packet.ts,
            protocol: flow_id.protocol,
            src_ip: flow_id.src_ip,
            dst_ip: flow_id.dst_ip,
            src_port: flow_id.src_port,
            dst_port: flow_id.dst_port,
            ttl_client: 0,
            ttl_server: 0,
            fwd_packets_count,
            bwd_packets_count,
            fwd_bytes: 0,
            bwd_bytes: 0,
            payloads: vec![],
            directions: vec![],
            flags: vec![],
            iat: vec![],
        }
    }

    fn new_from_udp(flow_id: FlowId, packets: Vec<UDPPacketInfo>) -> Self {
        let first_packet = packets.first().unwrap(); // we know there is a least one packet

        let directions: Vec<PacketDirection> = packets
            .iter()
            .map(|p| if p.src_ip == flow_id.src_ip { 
                    PacketDirection::Forward }
                    else {
                    PacketDirection::Backward
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


        FlowStats {
            timestamp: first_packet.ts,
            duration: packets.last().unwrap().ts - first_packet.ts,
            protocol: flow_id.protocol,
            src_ip: flow_id.src_ip,
            dst_ip: flow_id.dst_ip,
            src_port: flow_id.src_port,
            dst_port: flow_id.dst_port,
            ttl_client: 0,
            ttl_server: 0,
            fwd_packets_count,
            bwd_packets_count,
            fwd_bytes: 0,
            bwd_bytes: 0,
            payloads: vec![],
            directions: vec![],
            flags: vec![],
            iat: vec![],
        }
    }

}

fn flow_id_from_packet(data: &[u8]) -> FlowId {
    let eth_packet = ethernet::EthernetPacket::new(data).unwrap();
    let ip_packet = ipv4::Ipv4Packet::new(eth_packet.payload()).unwrap();

    let (protocol, src_port, dst_port) = match ip_packet.get_next_level_protocol() {
        IpNextHeaderProtocols::Tcp => {
            let tcp_packet = tcp::TcpPacket::new(ip_packet.payload()).unwrap();
            (
                Protocol::TCP,
                tcp_packet.get_source(),
                tcp_packet.get_destination(),
            )
        }
        IpNextHeaderProtocols::Udp => {
            let udp_packet = udp::UdpPacket::new(ip_packet.payload()).unwrap();
            (
                Protocol::UDP,
                udp_packet.get_source(),
                udp_packet.get_destination(),
            )
        }
        _ => panic!("Unsupported protocol"),
    };

    FlowId {
        protocol,
        src_ip: ip_packet.get_source(),
        dst_ip: ip_packet.get_destination(),
        src_port,
        dst_port,
    }
}

pub fn export_stats(file: &str, stats: Vec<FlowStats>) {


}

pub fn process_file(file: &str) -> Vec<FlowStats> {
    let file_in = BufReader::new(File::open(file).expect("Error opening file"));
    let mut pcap_reader = PcapReader::new(file_in).unwrap();
    let mut tcp_ongoing_flows: HashMap<FlowId, Vec<TCPPacketInfo>> = HashMap::new();
    let mut udp_ongoing_flows: HashMap<FlowId, Vec<UDPPacketInfo>> = HashMap::new();
    let mut finished_flows: Vec<FlowStats> = vec![];

    while let Some(packet) = pcap_reader.next_packet() {
        if let Ok(packet) = packet {
            let mut flow_id = flow_id_from_packet(&packet.data);
            flow_id.normalize();

            let packet_info: PacketInfo = packet.into();

            match packet_info {
                PacketInfo::TCP(packet) => {
                    let mut flow = tcp_ongoing_flows.entry(flow_id).or_default();
                    if let Some(last_packet) = flow.last() { // check if the flow is already finished
                        if last_packet.ts + DURATION_THRESHOLD < packet.ts {
                            // TODO
                            finished_flows.push(FlowStats::new_from_tcp(flow_id, tcp_ongoing_flows.remove(&flow_id).unwrap())); 
                            flow = tcp_ongoing_flows.entry(flow_id).or_default();
                        }
                    }
                    flow.push(packet); // TODO réordonner si on voit "SYN"
                },
                PacketInfo::UDP(packet) => {
                    let mut flow = udp_ongoing_flows.entry(flow_id).or_default();
                    if let Some(last_packet) = flow.last() { // check if the flow is already finished
                        if last_packet.ts + DURATION_THRESHOLD < packet.ts {
                            finished_flows.push(FlowStats::new_from_udp(flow_id, udp_ongoing_flows.remove(&flow_id).unwrap())); 
                            flow = udp_ongoing_flows.entry(flow_id).or_default();
                        }
                    }
                    flow.push(packet);
                },
                _ => todo!()
            }
        }
    }
    // unfinished flows
    for (k, v) in tcp_ongoing_flows.drain() {
        finished_flows.push(FlowStats::new_from_tcp(k,v)); 
    }
    for (k, v) in udp_ongoing_flows.drain() {
        finished_flows.push(FlowStats::new_from_udp(k,v)); 
    }
    finished_flows
}
