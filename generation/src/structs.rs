use pcap::PacketHeader;
use serde::Deserialize;
use std::cmp::Ordering;
use std::fmt::Debug;
use std::net::Ipv4Addr;
use std::time::Duration;

// A general wrapper to pass a seed along with actual data
#[derive(Debug, Clone)]
pub struct SeededData<T: Clone> {
    pub seed: u64,
    pub data: T,
}

// Stage 1 and 2 structures

#[allow(clippy::upper_case_acronyms)]
#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    TCP,
    UDP,
    ICMP,
    IGMP,
}

impl Protocol {
    pub fn iter() -> [Protocol; 1] {
        // TODO: add the other protocols when they are implemented
        [Protocol::TCP] //, Protocol::UDP, Protocol::ICMP]
    }

    pub fn wrap(&self, d: FlowData) -> Flow {
        match &self {
            Protocol::TCP => Flow::TCP(d),
            Protocol::UDP => Flow::UDP(d),
            Protocol::ICMP => Flow::ICMP(d),
            Protocol::IGMP => todo!(),
        }
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone)]
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

    // pub fn get_proto(&self) -> Protocol {
    //     match &self {
    //         Flow::TCP(_) => Protocol::TCP,
    //         Flow::UDP(_) => Protocol::UDP,
    //         Flow::ICMP(_) => Protocol::ICMP,
    //     }
    // }
}

#[derive(Debug, Clone)]
pub struct FlowData {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub ttl_client: u8,
    pub ttl_server: u8,
    pub fwd_packets_count: usize,
    pub bwd_packets_count: usize,
    pub timestamp: Duration,
    // pub total_duration: Duration,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Clone)]
pub struct Packet {
    pub header: PacketHeader,
    pub data: Vec<u8>,
}

impl Ord for Packet {
    fn cmp(&self, other: &Self) -> Ordering {
        self.header
            .ts
            .tv_sec
            .cmp(&other.header.ts.tv_sec)
            .then(self.header.ts.tv_usec.cmp(&other.header.ts.tv_usec))
    }
}

impl PartialOrd for Packet {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Packet {
    fn eq(&self, other: &Self) -> bool {
        self.header.ts.tv_usec == other.header.ts.tv_usec
            && self.header.ts.tv_sec == other.header.ts.tv_sec
    }
}

impl Eq for Packet {}

#[derive(Debug, Clone)]
pub struct Packets {
    pub packets: Vec<Packet>,
    pub directions: Vec<PacketDirection>,
    pub timestamps: Vec<Duration>,
    pub flow: Flow,
}
