use crate::structs::*;
use indicatif::ProgressBar;
use indicatif::ProgressStyle;
use pcap_file::pcap;
use pnet_packet::Packet;
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::{ethernet, ipv4, tcp, udp};
use std::collections::HashMap;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::Write;
use std::net::Ipv4Addr;
use std::time::Duration;

const DURATION_THRESHOLD: Duration = Duration::from_secs(600);

// timestamp,duration,protocol,src_ip,dst_ip,dst_port,fwd_packets,bwd_packets,fwd_bytes,bwd_bytes,time_sequence,payloads

#[derive(Debug)]
/// Flow statistics
pub struct FlowStats {
    pub timestamp: Duration,
    pub duration: Duration,
    pub protocol: L4Proto,
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
    pub payloads: Vec<Vec<u8>>,
    pub directions: Vec<PacketDirection>,
    pub flags: Vec<u8>, // empty when it is not TCP
    pub iat: Vec<Duration>,
}

#[allow(clippy::upper_case_acronyms)]
enum PacketInfo {
    TCP(TCPPacketInfo),
    UDP(UDPPacketInfo),
    ICMP(ICMPPacketInfo),
}

trait PacketInfoTrait {
    fn ts(&self) -> Duration;
    fn ttl(&self) -> u8;
    fn src_ip(&self) -> Ipv4Addr;
    fn payload(self) -> Vec<u8>;
    fn payload_size(&self) -> usize;
}

#[derive(Debug)]
struct TCPPacketInfo {
    payload: Vec<u8>,
    ts: Duration,
    flags: u8,
    src_ip: Ipv4Addr,
    ttl: u8,
}

impl PacketInfoTrait for TCPPacketInfo {
    fn ts(&self) -> Duration {
        self.ts
    }
    fn ttl(&self) -> u8 {
        self.ttl
    }
    fn src_ip(&self) -> Ipv4Addr {
        self.src_ip
    }
    fn payload(self) -> Vec<u8> {
        self.payload
    }
    fn payload_size(&self) -> usize {
        self.payload.len()
    }
}

#[derive(Debug)]
struct ICMPPacketInfo {
    // we assume no payload
    // we may need to add more fields to correctly generate them
    ts: Duration,
    src_ip: Ipv4Addr,
    ttl: u8,
}

impl PacketInfoTrait for ICMPPacketInfo {
    fn ts(&self) -> Duration {
        self.ts
    }
    fn ttl(&self) -> u8 {
        self.ttl
    }
    fn src_ip(&self) -> Ipv4Addr {
        self.src_ip
    }
    fn payload(self) -> Vec<u8> {
        vec![]
    }
    fn payload_size(&self) -> usize {
        0
    }
}

#[derive(Debug)]
struct UDPPacketInfo {
    payload: Vec<u8>,
    ts: Duration,
    src_ip: Ipv4Addr,
    ttl: u8,
}

impl PacketInfoTrait for UDPPacketInfo {
    fn ts(&self) -> Duration {
        self.ts
    }
    fn ttl(&self) -> u8 {
        self.ttl
    }
    fn src_ip(&self) -> Ipv4Addr {
        self.src_ip
    }
    fn payload(self) -> Vec<u8> {
        self.payload
    }
    fn payload_size(&self) -> usize {
        self.payload.len()
    }
}

impl From<pcap::PcapPacket<'_>> for PacketInfo {
    fn from(p: pcap::PcapPacket<'_>) -> PacketInfo {
        let eth_packet = ethernet::EthernetPacket::new(&p.data).unwrap();
        let ip_packet = ipv4::Ipv4Packet::new(eth_packet.payload()).unwrap();
        let ttl = ip_packet.get_ttl();

        match ip_packet.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp => {
                let tcp_packet = tcp::TcpPacket::new(ip_packet.payload()).unwrap();
                PacketInfo::TCP(TCPPacketInfo {
                    payload: tcp_packet.payload().to_vec(),
                    ts: p.timestamp,
                    flags: tcp_packet.get_flags(),
                    src_ip: ip_packet.get_source(),
                    ttl,
                })
            }
            IpNextHeaderProtocols::Udp => {
                let udp_packet = udp::UdpPacket::new(ip_packet.payload()).unwrap();
                PacketInfo::UDP(UDPPacketInfo {
                    payload: udp_packet.payload().to_vec(),
                    ts: p.timestamp,
                    src_ip: ip_packet.get_source(),
                    ttl,
                })
            }
            IpNextHeaderProtocols::Icmp => PacketInfo::ICMP(ICMPPacketInfo {
                ts: p.timestamp,
                src_ip: ip_packet.get_source(),
                ttl,
            }),

            _ => {
                // log::error!("Unsupported protocol: {proto}");
                panic!("Unsupported protocol")
            }
        }
    }
}

impl FlowStats {
    /// Extract flow statistics from a flow
    fn process_packets<T: PacketInfoTrait>(flow_id: FlowId, packets: Vec<T>) -> FlowStats {
        let first_packet = packets.first().unwrap(); // we know there is a least one packet
        let timestamp = first_packet.ts();
        let duration = packets.last().unwrap().ts() - first_packet.ts();

        let iat: Vec<Duration> = packets
            .windows(2)
            .map(|packets| packets[1].ts() - packets[0].ts())
            .collect();

        let fwd_bytes: usize = packets
            .iter()
            .filter_map(|p| {
                if p.src_ip() == flow_id.src_ip {
                    Some(p.payload_size())
                } else {
                    None
                }
            })
            .sum();

        let bwd_bytes: usize = packets
            .iter()
            .filter_map(|p| {
                if p.src_ip() != flow_id.src_ip {
                    Some(p.payload_size())
                } else {
                    None
                }
            })
            .sum();

        // use the first TTL we find. We assume the TTLs are constant
        // we could use the median value instead
        let ttl_client = packets
            .iter()
            .find(|p| p.src_ip() == flow_id.src_ip)
            .map(|p| p.ttl())
            .unwrap_or(0);

        let ttl_server = packets
            .iter()
            .find(|p| p.src_ip() != flow_id.src_ip)
            .map(|p| p.ttl())
            .unwrap_or(0);

        let directions: Vec<PacketDirection> = packets
            .iter()
            .map(|p| {
                if p.src_ip() == flow_id.src_ip {
                    PacketDirection::Forward
                } else {
                    PacketDirection::Backward
                }
            })
            .collect();

        let fwd_packets_count = directions
            .iter()
            .filter(|&d| *d == PacketDirection::Forward)
            .count();

        let bwd_packets_count = directions
            .iter()
            .filter(|&d| *d == PacketDirection::Backward)
            .count();

        let payloads: Vec<Vec<u8>> = packets.into_iter().map(|p| p.payload()).collect();

        FlowStats {
            timestamp,
            duration,
            protocol: flow_id.protocol,
            src_ip: flow_id.src_ip,
            dst_ip: flow_id.dst_ip,
            src_port: flow_id.src_port,
            dst_port: flow_id.dst_port,
            ttl_client,
            ttl_server,
            fwd_packets_count,
            bwd_packets_count,
            fwd_bytes,
            bwd_bytes,
            payloads,
            directions,
            flags: vec![],
            iat,
        }
    }

    fn new_from_tcp(flow_id: FlowId, packets: Vec<TCPPacketInfo>) -> Self {
        // get the flags before the packets are consumed
        let flags = packets.iter().map(|p| p.flags).collect();
        let mut stats = Self::process_packets(flow_id, packets);
        stats.flags = flags;
        stats
    }

    fn new_from_udp(flow_id: FlowId, packets: Vec<UDPPacketInfo>) -> Self {
        Self::process_packets(flow_id, packets)
    }

    fn new_from_icmp(flow_id: FlowId, packets: Vec<ICMPPacketInfo>) -> Self {
        Self::process_packets(flow_id, packets)
    }
}

fn flow_id_from_packet(data: &[u8]) -> Option<FlowId> {
    let eth_packet = ethernet::EthernetPacket::new(data).unwrap();
    let ip_packet = ipv4::Ipv4Packet::new(eth_packet.payload()).unwrap();

    let (protocol, src_port, dst_port) = match ip_packet.get_next_level_protocol() {
        IpNextHeaderProtocols::Tcp => {
            if let Some(tcp_packet) = tcp::TcpPacket::new(ip_packet.payload()) {
                (
                    L4Proto::TCP,
                    tcp_packet.get_source(),
                    tcp_packet.get_destination(),
                )
            } else {
                return None;
            }
        }
        IpNextHeaderProtocols::Udp => {
            let udp_packet = udp::UdpPacket::new(ip_packet.payload()).unwrap();
            (
                L4Proto::UDP,
                udp_packet.get_source(),
                udp_packet.get_destination(),
            )
        }
        IpNextHeaderProtocols::Icmp => (L4Proto::ICMP, 0, 0),

        _ => {
            // log::error!("Unsupported protocol: {proto}");
            return None;
        }
    };

    Some(FlowId {
        protocol,
        src_ip: ip_packet.get_source(),
        dst_ip: ip_packet.get_destination(),
        src_port,
        dst_port,
    })
}

/// Export flow statistics to a file
pub fn export_stats(file: &str, stats: Vec<FlowStats>, include_payloads: bool) {
    let file = File::create(file).expect("Cannot open file");
    let mut output = BufWriter::new(file);
    let header = if include_payloads {
        "timestamp,duration,protocol,src_ip,dst_ip,src_port,dst_port,ttl_client,ttl_server,fwd_packets_count,bwd_packets_count,fwd_bytes,bwd_bytes,payloads,directions,flags,iat"
    } else {
        "timestamp,duration,protocol,src_ip,dst_ip,src_port,dst_port,ttl_client,ttl_server,fwd_packets_count,bwd_packets_count,fwd_bytes,bwd_bytes,directions,flags,iat"
    };
    writeln!(output, "{header}").expect("Error during CSV writing");
    for f in stats.into_iter() {
        let iat: Vec<u128> = f.iat.iter().map(|d| d.as_millis()).collect();
        if include_payloads {
            writeln!(
                output,
                "{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {:?}, {:?}, {:?}, {:?}",
                f.timestamp.as_millis(),
                f.duration.as_millis(),
                f.protocol,
                f.src_ip,
                f.dst_ip,
                f.src_port,
                f.dst_port,
                f.ttl_client,
                f.ttl_server,
                f.fwd_packets_count,
                f.bwd_packets_count,
                f.fwd_bytes,
                f.bwd_bytes,
                f.payloads,
                f.directions,
                f.flags,
                iat
            )
            .expect("Error during CSV writing");
        } else {
            writeln!(
                output,
                "{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {:?}, {:?}, {:?}",
                f.timestamp.as_millis(),
                f.duration.as_millis(),
                f.protocol,
                f.src_ip,
                f.dst_ip,
                f.src_port,
                f.dst_port,
                f.ttl_client,
                f.ttl_server,
                f.fwd_packets_count,
                f.bwd_packets_count,
                f.fwd_bytes,
                f.bwd_bytes,
                f.directions,
                f.flags,
                iat
            )
            .expect("Error during CSV writing");
        }
    }
}

/// Extract flow statistics from a file
pub fn process_file(file: &str) -> Vec<FlowStats> {
    let file_in = BufReader::new(File::open(file).expect("Error opening file"));
    let mut pcap_reader = pcap::PcapReader::new(file_in).unwrap();
    let mut tcp_ongoing_flows: HashMap<FlowId, Vec<TCPPacketInfo>> = HashMap::new();
    let mut udp_ongoing_flows: HashMap<FlowId, Vec<UDPPacketInfo>> = HashMap::new();
    let mut icmp_ongoing_flows: HashMap<FlowId, Vec<ICMPPacketInfo>> = HashMap::new();
    let mut finished_flows: Vec<FlowStats> = vec![];

    while let Some(packet) = pcap_reader.next_packet() {
        if let Ok(packet) = packet {
            if let Some(mut flow_id) = flow_id_from_packet(&packet.data) {
                flow_id.normalize();

                let packet_info: PacketInfo = packet.into();

                match packet_info {
                    PacketInfo::TCP(packet) => {
                        let mut flow = tcp_ongoing_flows.entry(flow_id).or_default();
                        if let Some(last_packet) = flow.last() {
                            // check if the flow is already finished
                            if last_packet.ts + DURATION_THRESHOLD < packet.ts {
                                // TODO
                                finished_flows.push(FlowStats::new_from_tcp(
                                    flow_id,
                                    tcp_ongoing_flows.remove(&flow_id).unwrap(),
                                ));
                                flow = tcp_ongoing_flows.entry(flow_id).or_default();
                            }
                        }
                        flow.push(packet); // TODO réordonner si on voit "SYN"
                    }
                    PacketInfo::UDP(packet) => {
                        let mut flow = udp_ongoing_flows.entry(flow_id).or_default();
                        if let Some(last_packet) = flow.last() {
                            // check if the flow is already finished
                            if last_packet.ts + DURATION_THRESHOLD < packet.ts {
                                finished_flows.push(FlowStats::new_from_udp(
                                    flow_id,
                                    udp_ongoing_flows.remove(&flow_id).unwrap(),
                                ));
                                flow = udp_ongoing_flows.entry(flow_id).or_default();
                            }
                        }
                        flow.push(packet);
                    }
                    PacketInfo::ICMP(packet) => {
                        let mut flow = icmp_ongoing_flows.entry(flow_id).or_default();
                        if let Some(last_packet) = flow.last() {
                            // check if the flow is already finished
                            if last_packet.ts + DURATION_THRESHOLD < packet.ts {
                                finished_flows.push(FlowStats::new_from_icmp(
                                    flow_id,
                                    icmp_ongoing_flows.remove(&flow_id).unwrap(),
                                ));
                                flow = icmp_ongoing_flows.entry(flow_id).or_default();
                            }
                        }
                        flow.push(packet);
                    }
                }
            }
        }
    }
    // unfinished flows
    for (k, v) in tcp_ongoing_flows.drain() {
        finished_flows.push(FlowStats::new_from_tcp(k, v));
    }
    for (k, v) in udp_ongoing_flows.drain() {
        finished_flows.push(FlowStats::new_from_udp(k, v));
    }
    for (k, v) in icmp_ongoing_flows.drain() {
        finished_flows.push(FlowStats::new_from_icmp(k, v));
    }

    finished_flows
}

/// Remove the Fos-R taint (i.e., the third IP flag bit) from a pcap file
pub fn untaint_file(input: &str, output: &str) {
    let file_out = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(output)
        .expect("Error opening or creating file");
    let mut pcap_writer =
        pcap::PcapWriter::new(BufWriter::new(file_out)).expect("Error writing file");

    let mut count = 0;
    {
        // count the number of packet so we can put a progress bar
        let file_in = BufReader::new(File::open(input).expect("Error opening file"));
        let mut pcap_reader = pcap::PcapReader::new(file_in).unwrap();
        while pcap_reader.next_packet().is_some() {
            count += 1;
        }
    }
    let file_in = BufReader::new(File::open(input).expect("Error opening file"));
    let mut pcap_reader = pcap::PcapReader::new(file_in).unwrap();

    // setup the progress bar
    let pb = ProgressBar::new(count);
    pb.set_style(
        ProgressStyle::with_template("{spinner:.green} Untainting [{wide_bar}] ({eta})").unwrap(),
    );

    while let Some(packet) = pcap_reader.next_packet() {
        let mut packet = packet.expect("Error during packet parsing");
        // let packet = packet.into_owned();
        let data = packet.data.to_mut();
        // let mut eth_packet = ethernet::MutableEthernetPacket::new(&mut data).unwrap();
        let ip_start = ethernet::MutableEthernetPacket::minimum_packet_size();
        let mut ipv4_packet = ipv4::MutableIpv4Packet::new(&mut data[ip_start..]).unwrap();
        let ip_flags = ipv4_packet.get_flags();
        ipv4_packet.set_flags(ip_flags & 0b011);
        ipv4_packet.set_checksum(ipv4::checksum(&ipv4_packet.to_immutable()));
        pb.inc(1);
        pcap_writer.write_packet(&packet).unwrap();
    }
    pb.finish();
}
