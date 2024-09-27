use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

pub struct Packet {
    // should be replaced by the Packet structure defined in the network library
}

#[derive(Debug,Clone,Copy)]
pub enum PacketDirection {
    Forward, // client to server
    Backward, // server to client
}

#[derive(Debug,Clone,Copy)]
pub enum PayloadType {
    Empty,
    Print,
    LowEntropy,
    HighEntropy
}

pub trait Protocol {
    fn get_direction(&self) -> PacketDirection;
    fn get_iat(&self) -> Duration;
}

pub trait EdgeType : Copy {}

#[derive(Debug)]
pub struct PacketsIR<T: Protocol> { // Intermediate representation (as output by stage 2)
    pub packets_info: Vec<T>,
    pub flow: Flow
}

#[derive(Debug)]
pub enum Flow {
    TCPFlow(FlowData),
    UDPFlow(FlowData),
    ICMPFlow(FlowData)
}

#[derive(Debug)]
pub struct FlowData { // Output of stage 1
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub recorded_ttl_client: u8,
    pub recorded_ttl_server: u8,
    pub initial_ttl_client: u8,
    pub initial_ttl_server: u8,
    pub fwd_packets_count: u32,
    pub bwd_packets_count: u32,
    pub fwd_total_payload_length: u32,
    pub bwd_total_payload_length: u32,
    pub timestamp: Instant,
    pub total_duration: Duration
}
