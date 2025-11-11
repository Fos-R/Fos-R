use chrono::{DateTime, FixedOffset};
use pcap_file::pcap;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt::{Debug, Display};
use std::net::Ipv4Addr;
use std::time::Duration;
use thingbuf::Recycle;

/// A general wrapper to pass a seed along with actual data
#[derive(Debug, Clone)]
pub struct SeededData<T: Clone> {
    pub seed: u64,
    pub data: T,
}

// Stage 0 structure

#[derive(Debug, Clone)]
pub struct TimePoint {
    pub unix_time: Duration,
    pub date_time: DateTime<FixedOffset>,
}

// Stage 1 and 2 structures

#[allow(clippy::upper_case_acronyms)]
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    // TODO: renommer en L4Protocol pour éviter toute confusion
    TCP,
    UDP,
    ICMP,
}

// TODO: refaire proprement
impl From<String> for Protocol {
    fn from(s: String) -> Protocol {
        match s.as_str() {
            "TCP" => Protocol::TCP,
            "UDP" => Protocol::UDP,
            "ICMP" => Protocol::ICMP,
            _ => todo!(),
        }
    }
}

impl Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::TCP => write!(f, "TCP"),
            Protocol::UDP => write!(f, "UDP"),
            Protocol::ICMP => write!(f, "ICMP"),
        }
    }
}

impl Protocol {
    pub fn iter() -> [Protocol; 2] {
        // TODO: add the other protocols when they are implemented
        [Protocol::TCP, Protocol::UDP] //, Protocol::ICMP]
    }

    pub fn get_protocol_number(&self) -> u8 {
        match &self {
            Protocol::TCP => 6,
            Protocol::UDP => 17,
            Protocol::ICMP => 1,
        }
    }

    pub fn wrap(&self, d: FlowData) -> Flow {
        match &self {
            Protocol::TCP => Flow::TCP(d),
            Protocol::UDP => Flow::UDP(d),
            Protocol::ICMP => Flow::ICMP(d),
        }
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, Copy)]
pub enum Flow {
    TCP(FlowData),
    UDP(FlowData),
    ICMP(FlowData),
}

impl Flow {
    pub fn get_data(&self) -> &FlowData {
        match &self {
            Flow::TCP(data) => data,
            Flow::UDP(data) => data,
            Flow::ICMP(data) => data,
        }
    }

    pub fn get_data_mut(&mut self) -> &mut FlowData {
        match self {
            Flow::TCP(data) => data,
            Flow::UDP(data) => data,
            Flow::ICMP(data) => data,
        }
    }

    pub fn get_flow_id(&self) -> FlowId {
        let d = self.get_data();
        FlowId {
            protocol: self.get_proto(),
            src_ip: d.src_ip,
            dst_ip: d.dst_ip,
            src_port: d.src_port,
            dst_port: d.dst_port,
        }
    }

    pub fn get_proto(&self) -> Protocol {
        match &self {
            Flow::TCP(_) => Protocol::TCP,
            Flow::UDP(_) => Protocol::UDP,
            Flow::ICMP(_) => Protocol::ICMP,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FlowData {
    // In online mode, the local IP will always be the source
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub ttl_client: u8,
    pub ttl_server: u8,
    pub fwd_packets_count: usize,
    pub bwd_packets_count: usize,
    pub timestamp: Duration,
}

impl From<Flow> for FlowData {
    fn from(f: Flow) -> FlowData {
        match f {
            Flow::TCP(data) => data,
            Flow::UDP(data) => data,
            Flow::ICMP(data) => data,
        }
    }
}

// Stage 2 structures

#[derive(Debug, Clone)]
pub enum PayloadType {
    Empty,
    Text(&'static Vec<Vec<u8>>),
    Replay(&'static Vec<Vec<u8>>),
    Random(Vec<usize>),
}

pub trait EdgeType: Debug + Clone {
    fn get_payload_type(&self) -> &PayloadType;
    fn get_direction(&self) -> PacketDirection;
}

// Stage 2 and 3 structures

#[derive(Debug, Clone, Copy)]
#[allow(unused)]
pub enum NoiseType {
    None,
    Deleted,
    Reemitted,
    Transposed,
    Added,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum PacketDirection {
    Forward,  // client to server
    Backward, // server to client
}

impl PacketDirection {
    pub fn into_reverse(self) -> PacketDirection {
        match self {
            PacketDirection::Forward => PacketDirection::Backward,
            PacketDirection::Backward => PacketDirection::Forward,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Payload {
    Empty,
    Replay(&'static Vec<u8>),
    Random(usize),
}

impl Payload {
    pub fn get_payload_size(&self) -> usize {
        match &self {
            Payload::Empty => 0,
            Payload::Replay(l) => l.len(),
            Payload::Random(len) => *len,
        }
    }
}

pub trait PacketInfo: Clone + Debug {
    #[allow(unused)]
    fn get_noise_type(&self) -> NoiseType;
    fn get_direction(&self) -> PacketDirection;
    fn get_ts(&self) -> Duration;
    fn set_ts(&mut self, ts: Duration);
}

#[derive(Debug, Clone)]
pub struct PacketsIR<T: PacketInfo> {
    // Intermediate representation (as output by stage 2)
    pub packets_info: Vec<T>,
    pub flow: Flow,
}

// Stage 3 structures
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Packet {
    pub timestamp: Duration,
    pub data: Vec<u8>,
}

impl From<pcap::PcapPacket<'_>> for Packet {
    fn from(p: pcap::PcapPacket<'_>) -> Packet {
        Packet {
            timestamp: p.timestamp,
            data: p.data.into_owned(),
        }
    }
}

impl Packet {
    pub fn get_mutable_ip_packet(&mut self) -> Option<pnet_packet::ipv4::MutableIpv4Packet<'_>> {
        let eth_offset = pnet_packet::ethernet::EthernetPacket::minimum_packet_size();
        let ip_packet = pnet_packet::ipv4::MutableIpv4Packet::new(&mut self.data[eth_offset..])?;
        Some(ip_packet)
    }
}

/// Used for packet ordering before pcap export
impl Ord for Packet {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.timestamp == other.timestamp {
            self.data.cmp(&other.data) // use data in case both timestamps are equal
        } else {
            self.timestamp.cmp(&other.timestamp)
        }
    }
}

impl PartialOrd for Packet {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone)]
pub struct Packets {
    pub packets: Vec<Packet>,
    pub directions: Vec<PacketDirection>,
    pub timestamps: Vec<Duration>,
    pub flow: Flow,
}

impl Packets {
    pub fn clear(&mut self) {
        self.packets.clear();
        self.directions.clear();
        self.timestamps.clear();
    }

    pub fn reverse(&mut self) {
        for d in self.directions.iter_mut() {
            *d = d.into_reverse();
        }
        let data = self.flow.get_data_mut();
        (data.src_ip, data.dst_ip) = (data.dst_ip, data.src_ip);
        (data.src_port, data.dst_port) = (data.dst_port, data.src_port);
        (data.ttl_client, data.ttl_server) = (data.ttl_server, data.ttl_client);
        (data.fwd_packets_count, data.bwd_packets_count) =
            (data.bwd_packets_count, data.fwd_packets_count);
    }
}

impl Default for Packets {
    fn default() -> Self {
        Packets {
            packets: Vec::with_capacity(150),
            directions: Vec::with_capacity(150),
            timestamps: Vec::with_capacity(150),
            flow: Flow::TCP(FlowData {
                src_ip: Ipv4Addr::new(1, 2, 3, 4),
                dst_ip: Ipv4Addr::new(5, 6, 7, 8),
                src_port: 0,
                dst_port: 0,
                ttl_client: 0,
                ttl_server: 0,
                fwd_packets_count: 0,
                bwd_packets_count: 0,
                timestamp: Duration::new(0, 0),
            }),
        }
    }
}

pub struct PacketsRecycler {}

impl Recycle<Packets> for PacketsRecycler {
    // Required methods
    fn new_element(&self) -> Packets {
        Packets::default()
    }
    fn recycle(&self, element: &mut Packets) {
        element.clear();
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct FlowId {
    pub protocol: Protocol,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
}

impl FlowId {
    /// Check whether a given flow is compatible with the current FlowId.
    /// Compatibility is based on matching source IP, destination IP, source port, and destination port.
    pub fn is_compatible(&self, f: &Flow) -> bool {
        let d = f.get_data();
        self.src_ip == d.src_ip
            && self.dst_ip == d.dst_ip
            && self.src_port == d.src_port
            && self.dst_port == d.dst_port
            && self.protocol == f.get_proto()
    }

    pub fn normalize(&mut self) {
        if self.src_ip > self.dst_ip
            || (self.src_ip == self.dst_ip && self.src_port > self.dst_port)
        {
            std::mem::swap(&mut self.src_ip, &mut self.dst_ip);
            std::mem::swap(&mut self.src_port, &mut self.dst_port);
        }
    }
}
