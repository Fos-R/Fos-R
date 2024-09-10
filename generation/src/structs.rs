use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

pub struct Packet {
    // should be replaced by the Packet structure defined in the network library
}

#[derive(Debug)]
pub enum PacketDirection {
    ClientToServer,
    ServerToClient
}

#[derive(Debug)]
pub enum PayloadType {
    Empty,
    Print,
    LowEntropy,
    HighEntropy
}

#[derive(Debug)]
pub struct TCPPacketInfo {
    payload_length: u32,
    payload_type: PayloadType,
    iat: Duration,
    direction: PacketDirection,
    s_flag: bool,
    a_flag: bool,
    f_flag: bool,
    r_flag: bool,
    u_flag: bool,
    p_flag: bool
}

#[derive(Debug)]
pub struct UDPPacketInfo {
    payload_length: u32,
    payload_type: PayloadType,
    iat: Duration,
    direction: PacketDirection
}

#[derive(Debug)]
pub struct ICMPPacketInfo {
    // we assume no payload
    // we may need to add more fields to correctly generate them
    iat: Duration,
    direction: PacketDirection
}

pub trait Protocol {
    fn get_direction(&self) -> PacketDirection;
    fn get_iat(&self) -> Duration;
}

impl Protocol for TCPPacketInfo {
    fn get_direction(&self) -> PacketDirection {
        self.direction
    }
    fn get_iat(&self) -> Duration {
        self.iat
    }
}

impl Protocol for UDPPacketInfo {
    fn get_direction(&self) -> PacketDirection {
        self.direction
    }
    fn get_iat(&self) -> Duration {
        self.iat
    }
}

impl Protocol for ICMPPacketInfo {
    fn get_direction(&self) -> PacketDirection {
        self.direction
    }
    fn get_iat(&self) -> Duration {
        self.iat
    }
}

#[derive(Debug)]
pub struct PacketsIR<T: Protocol> { // Intermediate representation (as output by stage 2)
    packets_info: Vec<T>,
    flow: Flow
}

#[derive(Debug)]
pub enum Flow {
    TCPFlow(FlowData),
    UDPFlow(FlowData),
    ICMPFlow(FlowData)
}

#[derive(Debug)]
pub struct FlowData { // Output of stage 1
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    recorded_ttl_client: u8,
    recorded_ttl_server: u8,
    initial_ttl_client: u8,
    initial_ttl_server: u8,
    fwd_packets_count: u32,
    bwd_packets_count: u32,
    fwd_total_payload_length: u32,
    bwd_total_payload_length: u32,
    timestamp: Instant,
    total_duration: Duration
}
