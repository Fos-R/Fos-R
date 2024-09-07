use std::time::{Duration, Instant};
use crate::structs;

pub struct Stage3 {} // In the future, add network/system configuration here

impl Stage3 {

    pub fn new() -> Self {
        Stage3 {}
    }

    /// Generate TCP packets from an intermediate representation
    pub fn generate_tcp_packets(&self, input: &structs::PacketsIR<structs::TCPPacketInfo>) -> Vec<structs::Packet> {
        panic!("Not implemented");
    }

    /// Generate UDP packets from an intermediate representation
    pub fn generate_udp_packets(&self, input: &structs::PacketsIR<structs::UDPPacketInfo>) -> Vec<structs::Packet> {
        panic!("Not implemented");
    }

}
