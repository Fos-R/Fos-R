use crate::icmp::*;
use crate::stats::Stats;
use crate::structs::*;
use crate::tcp::*;
use crate::udp::*;
use crossbeam_channel::{Receiver, Sender};
use std::sync::Arc;

mod automaton;
/// An implementation of TADAM automaton for generation
pub mod tadam;

/// A trait for Stage 2 that generates packet metadata from flows
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

/// A set of Sender used by a Stage 2. Each Sender corresponds to a L4 protocol.
#[derive(Debug, Clone)]
pub struct S2Sender {
    pub tcp: Sender<SeededData<PacketsIR<TCPPacketInfo>>>,
    pub udp: Sender<SeededData<PacketsIR<UDPPacketInfo>>>,
    pub icmp: Sender<SeededData<PacketsIR<ICMPPacketInfo>>>,
}

pub struct S2Vector {
    pub tcp: Vec<SeededData<PacketsIR<TCPPacketInfo>>>,
    pub udp: Vec<SeededData<PacketsIR<UDPPacketInfo>>>,
    pub icmp: Vec<SeededData<PacketsIR<ICMPPacketInfo>>>,
}

/// Generate packet metadata from flows sends them progressively to a channel
pub fn run_channel(
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
        log::trace!("Generating packets info");
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

/// Generate packet metadata from flows and into a vector
pub fn run_vec(generator: impl Stage2, vec_s2: Vec<SeededData<Flow>>) -> S2Vector {
    log::trace!("Start S2");
    let mut vectors = S2Vector {
        tcp: Vec::with_capacity(
            vec_s2
                .iter()
                .filter(|f| matches!(f.data, Flow::TCP(_)))
                .count(),
        ),
        udp: Vec::with_capacity(
            vec_s2
                .iter()
                .filter(|f| matches!(f.data, Flow::UDP(_)))
                .count(),
        ),
        icmp: Vec::with_capacity(
            vec_s2
                .iter()
                .filter(|f| matches!(f.data, Flow::ICMP(_)))
                .count(),
        ),
    };
    for flow in vec_s2 {
        log::trace!("Generating packets info");
        match flow.data {
            Flow::TCP(data) => {
                if let Some(pir) = generator.generate_tcp_packets_info(SeededData {
                    seed: flow.seed,
                    data,
                }) {
                    vectors.tcp.push(pir);
                }
            }
            Flow::UDP(data) => {
                if let Some(pir) = generator.generate_udp_packets_info(SeededData {
                    seed: flow.seed,
                    data,
                }) {
                    vectors.udp.push(pir);
                }
            }
            Flow::ICMP(data) => {
                if let Some(pir) = generator.generate_icmp_packets_info(SeededData {
                    seed: flow.seed,
                    data,
                }) {
                    vectors.icmp.push(pir);
                }
            }
        }
    }
    log::trace!("S2 stops");
    vectors
}
