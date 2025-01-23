use crate::icmp::*;
use crate::structs::*;
use crate::tcp::*;
use crate::udp::*;
use crossbeam_channel::{Receiver, Sender};

mod automaton;
pub mod tadam;

pub trait Stage2: Clone + std::marker::Send + 'static {
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

#[derive(Debug, Clone)]
pub struct S2Sender {
    pub tcp: Sender<SeededData<PacketsIR<TCPPacketInfo>>>,
    pub udp: Sender<SeededData<PacketsIR<UDPPacketInfo>>>,
    pub icmp: Sender<SeededData<PacketsIR<ICMPPacketInfo>>>,
}

pub fn run(generator: impl Stage2, rx_s2: Receiver<SeededData<Flow>>, tx_s2: S2Sender) {
    log::trace!("Start S2");
    while let Ok(flow) = rx_s2.recv() {
        match flow.data {
            Flow::TCP(data) => {
                tx_s2
                    .tcp
                    .send(generator.generate_tcp_packets_info(SeededData {
                        seed: flow.seed,
                        data,
                    }))
                    .unwrap();
            }
            Flow::UDP(data) => {
                tx_s2
                    .udp
                    .send(generator.generate_udp_packets_info(SeededData {
                        seed: flow.seed,
                        data,
                    }))
                    .unwrap();
            }
            Flow::ICMP(data) => {
                tx_s2
                    .icmp
                    .send(generator.generate_icmp_packets_info(SeededData {
                        seed: flow.seed,
                        data,
                    }))
                    .unwrap();
            }
        }
    }
    log::trace!("S2 stops");
}
