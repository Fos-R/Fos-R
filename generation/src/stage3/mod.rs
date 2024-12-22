#![allow(unused)]

use crate::*;
use crate::tcp::*;
use crate::udp::*;
use crate::icmp::*;
use rand_pcg::Pcg32;
use rand::prelude::*;

pub struct Stage3 {
    taint: bool,
} // In the future, add network/system configuration here

impl Stage3 {

    pub fn new(taint: bool) -> Self {
        Stage3 { taint }
    }

    /// Generate TCP packets from an intermediate representation
    pub fn generate_tcp_packets(&self, input: SeededData<PacketsIR<TCPPacketInfo>>) -> SeededData<Packets> {
        let mut rng = Pcg32::seed_from_u64(input.seed);
        panic!("Not implemented");
    }

    /// Generate UDP packets from an intermediate representation
    pub fn generate_udp_packets(&self, input: SeededData<PacketsIR<UDPPacketInfo>>) -> SeededData<Packets> {
        let mut rng = Pcg32::seed_from_u64(input.seed);
        panic!("Not implemented");
    }

    /// Generate ICMP packets from an intermediate representation
    pub fn generate_icmp_packets(&self, input: SeededData<PacketsIR<ICMPPacketInfo>>) -> SeededData<Packets> {
        let mut rng = Pcg32::seed_from_u64(input.seed);
        panic!("Not implemented");
    }

}

pub fn insert_noise(data: &mut SeededData<Packets>) {
    panic!("Not implemented");
}

pub fn pcap_export(data: &Vec<Vec<u8>>, outfile: &String) {
    // TODO: sort the data by timestamp
    panic!("Not implemented");
}


