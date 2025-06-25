use crate::icmp::*;
use crate::structs::*;
use crate::tcp::*;
use crate::udp::*;
use crate::ui::Stats;
use crossbeam_channel::{Receiver, Sender};
use std::sync::Arc;

mod automaton;
pub mod tadam;

pub trait Stage2: Clone + std::marker::Send + 'static {
    fn generate_tcp_packets_info(
        &self,
        flow: SeededData<FlowData>,
    ) -> Option<SeededData<PacketsIR<TCPPacketInfo>>>;
    fn generate_udp_packets_info(
        &self,
        flow: SeededData<FlowData>,
    ) -> Option<SeededData<PacketsIR<UDPPacketInfo>>>;
    fn generate_icmp_packets_info(
        &self,
        flow: SeededData<FlowData>,
    ) -> Option<SeededData<PacketsIR<ICMPPacketInfo>>>;
}

#[derive(Debug, Clone)]
pub struct S2Sender {
    pub tcp: Sender<SeededData<PacketsIR<TCPPacketInfo>>>,
    pub udp: Sender<SeededData<PacketsIR<UDPPacketInfo>>>,
    pub icmp: Sender<SeededData<PacketsIR<ICMPPacketInfo>>>,
}

pub fn run(
    generator: impl Stage2,
    rx_s2: Receiver<SeededData<Flow>>,
    tx_s2: S2Sender,
    stats: Arc<Stats>,
) -> Result<(), Box<dyn std::error::Error>> {
    log::trace!("Start S2");
    for flow in rx_s2 {
        if stats.should_stop() {
            break;
        }

        match flow.data {
            Flow::TCP(data) => {
                if let Some(pir) = generator.generate_tcp_packets_info(SeededData {
                    seed: flow.seed,
                    data,
                }) {
                    tx_s2.tcp.send(pir)?;
                }
            }
            Flow::UDP(data) => {
                if let Some(pir) = generator.generate_udp_packets_info(SeededData {
                    seed: flow.seed,
                    data,
                }) {
                    tx_s2.udp.send(pir)?;
                }
            }
            Flow::ICMP(data) => {
                if let Some(pir) = generator.generate_icmp_packets_info(SeededData {
                    seed: flow.seed,
                    data,
                }) {
                    tx_s2.icmp.send(pir)?;
                }
            }
        }
    }
    log::trace!("S2 stops");
    Ok(())
}
