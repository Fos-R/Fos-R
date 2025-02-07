use crate::icmp::*;
use crate::structs::*;
use crate::tcp::*;
use crate::udp::*;

mod automaton;
pub mod replay;
pub mod tadam;

pub trait Stage2 {
    fn generate_tcp_packets_info(
        &self,
        flow: SeededData<FlowData>,
    ) -> SeededData<PacketsIR<TCPPacketInfo>>;
    fn generate_udp_packets_info(
        &self,
        flow: SeededData<FlowData>,
    ) -> SeededData<PacketsIR<UDPPacketInfo>>;
    fn generate_icmp_packets_info(
        &self,
        flow: SeededData<FlowData>,
    ) -> SeededData<PacketsIR<ICMPPacketInfo>>;
}
