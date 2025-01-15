use crate::structs::*;
use crate::tcp::*;
use crate::udp::*;
use crate::icmp::*;

mod automaton;
pub mod tadam;
pub mod replay;

pub trait Stage2 {
    fn generate_tcp_packets_info(&self, flow: SeededData<FlowData>) -> SeededData<PacketsIR<TCPPacketInfo>>;
    fn generate_udp_packets_info(&self, flow: SeededData<FlowData>) -> SeededData<PacketsIR<UDPPacketInfo>>;
    fn generate_icmp_packets_info(&self, flow: SeededData<FlowData>) -> SeededData<PacketsIR<ICMPPacketInfo>>;
}
