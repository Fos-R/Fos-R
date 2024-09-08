use std::time::{Duration, Instant};
use crate::*;

pub struct Stage3 {} // In the future, add network/system configuration here

impl Stage3 {

    pub fn new() -> Self {
        Stage3 {}
    }

    /// Generate TCP packets from an intermediate representation
    pub fn generate_tcp_packets(&self, input: &PacketsIR<TCPPacketInfo>) -> Vec<Packet> {
        panic!("Not implemented");
    }

    /// Generate UDP packets from an intermediate representation
    pub fn generate_udp_packets(&self, input: &PacketsIR<UDPPacketInfo>) -> Vec<Packet> {
        panic!("Not implemented");
    }

    /// Generate ICMP packets from an intermediate representation
    pub fn generate_icmp_packets(&self, input: &PacketsIR<ICMPPacketInfo>) -> Vec<Packet> {
        panic!("Not implemented");
    }

}
