use crate::structs::*;
use crate::tcp::*;
use crate::udp::*;
use crate::icmp::*;
use crossbeam_channel::{Sender, Receiver};

mod automaton;
pub mod tadam;
pub mod replay;

pub trait Stage2 {
    fn generate_tcp_packets_info(&self, flow: SeededData<FlowData>) -> SeededData<PacketsIR<TCPPacketInfo>>;
    fn generate_udp_packets_info(&self, flow: SeededData<FlowData>) -> SeededData<PacketsIR<UDPPacketInfo>>;
    fn generate_icmp_packets_info(&self, flow: SeededData<FlowData>) -> SeededData<PacketsIR<ICMPPacketInfo>>;
}

pub fn run(generator: impl Stage2, rx_s2: Receiver<SeededData<Flow>>, tx_s2_tcp: Sender<SeededData<PacketsIR<TCPPacketInfo>>>, tx_s2_udp: Sender<SeededData<PacketsIR<UDPPacketInfo>>>, tx_s2_icmp: Sender<SeededData<PacketsIR<ICMPPacketInfo>>>) {
    log::trace!("Start S2");
    while let Ok(flow) = rx_s2.recv() {
        log::trace!("S2 generates");
        match flow.data {
            Flow::TCP(data) => {
                tx_s2_tcp.send(generator.generate_tcp_packets_info(SeededData { seed : flow.seed, data })).unwrap();
            },
            Flow::UDP(data) => {
                tx_s2_udp.send(generator.generate_udp_packets_info(SeededData { seed : flow.seed, data })).unwrap();
            },
            Flow::ICMP(data) => {
                tx_s2_icmp.send(generator.generate_icmp_packets_info(SeededData { seed : flow.seed, data })).unwrap();
            },
        }
    }
    log::trace!("S2 stops");
}
