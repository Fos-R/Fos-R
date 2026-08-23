use chrono::{DateTime, FixedOffset};
use pcap_file::pcap;
use pnet::util::MacAddr;
use rand_distr::Uniform;
use rand_distr::weighted::WeightedIndex;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt::{Debug, Display};
use std::net::Ipv4Addr;
use std::time::Duration;
use strum::{Display, EnumIter, EnumString, IntoEnumIterator};
use thingbuf::Recycle;
use std::str::FromStr;

/// A general wrapper to pass a seed along with actual data
#[derive(Debug, Clone)]
pub struct SeededData<T: Clone> {
    pub seed: u64,
    pub data: T,
}

/// Stage 1 structure
#[derive(Debug, Clone)]
pub struct TimePoint {
    pub unix_time: Duration,
    pub date_time: DateTime<FixedOffset>,
}

// Stage 2 and 3 structures

/// A transport protocol
#[allow(clippy::upper_case_acronyms)]
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash, EnumString)]
#[serde(rename_all_fields = "UPPERCASE")]
#[strum(
    parse_err_fn = String::from,
    parse_err_ty = String
)]
pub enum L4Proto {
    #[serde(alias = "tcp")]
    TCP,
    #[serde(alias = "udp")]
    UDP,
    #[serde(alias = "icmp")]
    ICMP,
}

/// Connection states, adapted from Zeek
/// <https://docs.zeek.org/en/master/scripts/base/protocols/conn/main.zeek.html#field-Conn::Info$conn_state>
#[allow(clippy::upper_case_acronyms)]
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash, EnumString)]
#[strum(
    parse_err_fn = String::from,
    parse_err_ty = String
)]
pub enum TCPConnState {
    /// Normal establishment and termination
    SF,
    /// Originator sent a SYN followed by a FIN, we never saw a SYN ACK from the responder (hence the connection was “half” open)
    SH,
    /// Connection aborted (RST)
    RST,
    /// Connection attempt seen, no reply
    S0,
    /// Connection attempt rejected
    REJ,
    /// For non-TCP communication
    #[strum(serialize="none")]
    NoState,
}

impl Display for L4Proto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            L4Proto::TCP => write!(f, "TCP"),
            L4Proto::UDP => write!(f, "UDP"),
            L4Proto::ICMP => write!(f, "ICMP"),
        }
    }
}

impl L4Proto {
    pub fn iter() -> [L4Proto; 2] {
        // TODO: add the other protocols when they are implemented
        [L4Proto::TCP, L4Proto::UDP] //, L4Proto::ICMP]
    }

    pub fn get_protocol_number(&self) -> u8 {
        match &self {
            L4Proto::TCP => 6,
            L4Proto::UDP => 17,
            L4Proto::ICMP => 1,
        }
    }

    pub fn wrap(&self, d: FlowData, c: Option<TCPConnState>) -> Flow {
        match &self {
            L4Proto::TCP => Flow::TCP(d, c.unwrap_or(TCPConnState::SF)), // FIXME
            L4Proto::UDP => {
                // assert!(c.is_none());
                Flow::UDP(d)
            }
            L4Proto::ICMP => {
                // assert!(c.is_none());
                Flow::ICMP(d)
            }
        }
    }
}

#[derive(
    Serialize, Deserialize, Debug, Clone, Copy, Eq, Hash, PartialEq, Display, EnumIter,
)]
#[allow(clippy::upper_case_acronyms)]
#[serde(rename_all = "lowercase")]
/// A list of application layer protocol
pub enum L7Proto {
    // Dedicated variants for well-known protocols
    HTTP,
    HTTPS,
    SSH,
    DNS,
    DHCP,
    SMTP,
    Telnet,
    IMAPS,
    MQTT,
    KMS,
    MulticastDNS,
    NTP, // TODO complete
    // Joker variant for everything else
    Unknown(&'static str), // &'static str costs a little leak (a few bytes) but make this enum
                           // Copy, which is very convenient
}

impl FromStr for L7Proto {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        Ok(match s.to_uppercase().replace(" ", "").as_str().trim() {
            "HTTP" => L7Proto::HTTP,
            "HTTPS" => L7Proto::HTTPS,
            "SSH" => L7Proto::SSH,
            "DNS" => L7Proto::DNS,
            "DHCP" => L7Proto::DHCP,
            "SMTP" => L7Proto::SMTP,
            "TELNET" => L7Proto::Telnet,
            "IMAPS" => L7Proto::IMAPS,
            "MQTT" => L7Proto::MQTT,
            "KMS" => L7Proto::KMS,
            "MULTICASTDNS" => L7Proto::MulticastDNS,
            "NTP" => L7Proto::NTP,
            _ => L7Proto::Unknown(String::from(s).leak()),
        })
    }
}

impl L7Proto {
    /// All protocol names as strings.
    pub fn all_names() -> Vec<String> {
        L7Proto::iter().map(|p| p.to_string()).collect()
    }

    /// Human-facing label for UI display (e.g. "mDNS", "HTTP").
    /// Unlike `Display` (lowercase for config use), this preserves capitalization.
    pub fn ui_label(&self) -> &'static str {
        match self {
            L7Proto::HTTP => "HTTP",
            L7Proto::HTTPS => "HTTPS",
            L7Proto::SSH => "SSH",
            L7Proto::DNS => "DNS",
            L7Proto::DHCP => "DHCP",
            L7Proto::SMTP => "SMTP",
            L7Proto::Telnet => "Telnet",
            L7Proto::IMAPS => "IMAPS",
            L7Proto::MQTT => "MQTT",
            L7Proto::KMS => "KMS",
            L7Proto::MulticastDNS => "mDNS",
            L7Proto::NTP => "NTP",
            L7Proto::Unknown(s) => s,
        }
    }

    /// Default destination port that is used if a configuration file does not override it
    pub fn get_default_port(&self) -> u16 {
        match self {
            L7Proto::HTTP => 80,
            L7Proto::HTTPS => 443,
            L7Proto::SSH => 22,
            L7Proto::DNS => 53,
            L7Proto::DHCP => 67,
            L7Proto::SMTP => 587,
            L7Proto::Telnet => 23,
            L7Proto::IMAPS => 993,
            L7Proto::MQTT => 1883,
            L7Proto::KMS => 1688,
            L7Proto::MulticastDNS => 5353,
            L7Proto::NTP => 123,
            L7Proto::Unknown(_) => todo!(), // TODO: should return an Option
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
/// The OS of an host. By default, assume Linux
pub enum OS {
    #[default]
    Linux,
    Windows,
}

impl Display for OS {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            OS::Linux => write!(f, "Linux"),
            OS::Windows => write!(f, "Windows"),
        }
    }
}

impl OS {
    pub fn get_initial_ttl(&self) -> u8 {
        match self {
            OS::Linux => 64,
            OS::Windows => 128,
        }
    }

    // Source: https://en.wikipedia.org/wiki/Ephemeral_port
    pub fn get_ephemeral_port_distr(&self) -> Uniform<u16> {
        match self {
            OS::Linux => Uniform::new(32768, 60999).unwrap(),
            OS::Windows => Uniform::new(49152, 65535).unwrap(),
        }
    }
}

/// A wrapper for transport layer flow
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, Copy)]
pub enum Flow {
    TCP(FlowData, TCPConnState),
    UDP(FlowData),
    ICMP(FlowData),
}

impl Flow {
    pub fn get_data(&self) -> &FlowData {
        match &self {
            Flow::TCP(data, _) | Flow::UDP(data) | Flow::ICMP(data) => data,
        }
    }

    pub fn get_data_mut(&mut self) -> &mut FlowData {
        match self {
            Flow::TCP(data, _) | Flow::UDP(data) | Flow::ICMP(data) => data,
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

    pub fn get_proto(&self) -> L4Proto {
        match &self {
            Flow::TCP(_, _) => L4Proto::TCP,
            Flow::UDP(_) => L4Proto::UDP,
            Flow::ICMP(_) => L4Proto::ICMP,
        }
    }
}

/// The data of a transport layer flow
#[derive(Debug, Clone, Copy)]
pub struct FlowData {
    // In online mode, the local IP will always be the source
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_mac: MacAddr,
    pub dst_mac: MacAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub ttl_client: u8,
    pub ttl_server: u8,
    pub packets_count_cluster: usize,
    pub fwd_packets_count: usize,
    pub bwd_packets_count: usize,
    pub timestamp: Duration,
    pub l7_proto: L7Proto,
}

impl From<Flow> for FlowData {
    fn from(f: Flow) -> FlowData {
        match f {
            Flow::TCP(data, _) | Flow::UDP(data) | Flow::ICMP(data) => data,
        }
    }
}

// Stage 3 structures

#[derive(Debug, Clone)]
/// Types of payload in the automata
pub enum PayloadType {
    /// No payload
    Empty,
    /// Payload is not random and will be replayed
    Binary(&'static Vec<Vec<u8>>, WeightedIndex<u64>),
}

pub(crate) trait EdgeType: Debug + Clone {
    fn get_payload_type(&self) -> &PayloadType;
    fn get_direction(&self) -> PacketDirection;
}

// Stage 3 and 4 structures

/// The direction of a packet
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum PacketDirection {
    /// client to server
    Forward,
    /// server to client
    Backward,
}

impl PacketDirection {
    pub fn into_reverse(self) -> PacketDirection {
        match self {
            PacketDirection::Forward => PacketDirection::Backward,
            PacketDirection::Backward => PacketDirection::Forward,
        }
    }
}

/// The payload of a packet
#[derive(Debug, Clone)]
pub enum Payload {
    /// No payload
    Empty,
    /// A replayed payload
    Binary(&'static Vec<u8>),
    /// A payload that will be randomly generated
    Random(usize),
}

impl Payload {
    pub fn get_payload_size(&self) -> usize {
        match &self {
            Payload::Empty => 0,
            Payload::Binary(l) => l.len(),
            Payload::Random(len) => *len,
        }
    }
}

pub trait PacketInfo: Clone + Debug {
    #[allow(unused)]
    fn get_direction(&self) -> PacketDirection;
    fn get_ts(&self) -> Duration;
    fn set_ts(&mut self, ts: Duration);
}

#[derive(Debug, Clone)]
/// The packets intermediate representation (as output by stage 3)
pub struct PacketsIR<T: PacketInfo> {
    pub packets_info: Vec<T>,
    pub flow: Flow,
}

// Stage 4 structures
#[derive(Debug, Clone, Eq, PartialEq)]
/// A packet, with a timestamp and some data
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
/// A set of packets from the same flow
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
            flow: Flow::UDP(FlowData {
                src_ip: Ipv4Addr::UNSPECIFIED,
                dst_ip: Ipv4Addr::UNSPECIFIED,
                src_mac: MacAddr::zero(),
                dst_mac: MacAddr::zero(),
                src_port: 0,
                dst_port: 0,
                ttl_client: 0,
                ttl_server: 0,
                packets_count_cluster: 0,
                fwd_packets_count: 0,
                bwd_packets_count: 0,
                timestamp: Duration::new(0, 0),
                l7_proto: L7Proto::HTTP,
            }),
        }
    }
}

/// The recycler used by thingbuf
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
/// A 5-uplet typically used to identify a flow
pub struct FlowId {
    pub protocol: L4Proto,
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
