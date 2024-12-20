#![allow(unused)]

use crate::*;
use crate::tcp::*;
use crate::udp::*;
use crate::icmp::*;
use rand_pcg::Pcg32;
use rand::prelude::*;

pub struct Stage3 {
    rng: Pcg32,
    taint: bool,
} // In the future, add network/system configuration here

impl Stage3 {

    pub fn new(seed: u64, taint: bool) -> Self {
        Stage3 { rng: Pcg32::seed_from_u64(seed), taint }
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

    pub fn pcap_export(&self, outfile: &String) {
        panic!("Not implemented");
    }

}
