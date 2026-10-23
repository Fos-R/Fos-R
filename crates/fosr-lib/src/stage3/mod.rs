use crate::icmp::IcmpPacketInfo;
use crate::stats::Stats;
use crate::structs::{
    EdgeType, Flow, FlowData, L4Proto, L7Proto, PacketDirection, PacketInfo, PacketsIR, SeededData,
    TcpConnState,
};
use crate::tcp::{TcpEdgeTuple, TcpPacketInfo, create_tcp_header, parse_tcp_symbol};
use crate::udp::{UdpEdgeTuple, UdpPacketInfo, create_udp_header, parse_udp_symbol};
use crossbeam_channel::{Receiver, Sender};
use std::sync::Arc;

mod automaton;
/// An implementation of TADAM automaton for generation
pub mod tadam;

/// A trait for Stage 3 that generates packet metadata from flows
pub trait Stage3: Clone + std::marker::Send + 'static {
    fn generate_tcp_packets_info(
        &self,
        flow: SeededData<FlowData>,
        conn_state: TcpConnState,
    ) -> Option<SeededData<PacketsIR<TcpPacketInfo>>>;
    fn generate_udp_packets_info(
        &self,
        flow: SeededData<FlowData>,
    ) -> Option<SeededData<PacketsIR<UdpPacketInfo>>>;
    fn generate_icmp_packets_info(
        &self,
        flow: SeededData<FlowData>,
    ) -> Option<SeededData<PacketsIR<IcmpPacketInfo>>>;
}

/// A set of Sender used by a Stage 3. Each Sender corresponds to a L4 protocol
#[derive(Debug, Clone)]
pub struct S3Sender {
    pub tcp: Sender<SeededData<PacketsIR<TcpPacketInfo>>>,
    pub udp: Sender<SeededData<PacketsIR<UdpPacketInfo>>>,
    pub icmp: Sender<SeededData<PacketsIR<IcmpPacketInfo>>>,
}

/// A set of Vector used by a Stage 3. Each Vector corresponds to a L4 protocol
pub struct S3Vector {
    pub tcp: Vec<SeededData<PacketsIR<TcpPacketInfo>>>,
    pub udp: Vec<SeededData<PacketsIR<UdpPacketInfo>>>,
    pub icmp: Vec<SeededData<PacketsIR<IcmpPacketInfo>>>,
}

/// Generate packet metadata from flows sends them progressively to a channel
pub fn run_channel(
    generator: impl Stage3,
    rx_s3: Receiver<SeededData<Flow>>,
    tx_s3: S3Sender,
    stats: Arc<Stats>,
) -> Result<(), Box<dyn std::error::Error>> {
    log::trace!("Start S3 (channel)");
    let mut count = 0;
    for flow in rx_s3 {
        if stats.should_stop() {
            break;
        }
        log::trace!("Generating packets info");
        match flow.data {
            Flow::Tcp(data, conn_state) => {
                if let Some(pir) = generator.generate_tcp_packets_info(
                    SeededData {
                        seed: flow.seed,
                        data,
                    },
                    conn_state,
                ) {
                    tx_s3.tcp.send(pir)?;
                }
            }
            Flow::Udp(data) => {
                if let Some(pir) = generator.generate_udp_packets_info(SeededData {
                    seed: flow.seed,
                    data,
                }) {
                    tx_s3.udp.send(pir)?;
                }
            }
            Flow::Icmp(data) => {
                if let Some(pir) = generator.generate_icmp_packets_info(SeededData {
                    seed: flow.seed,
                    data,
                }) {
                    tx_s3.icmp.send(pir)?;
                }
            }
        }
        count += 1;
    }
    log::trace!("S3 stops: {count} elements received");
    Ok(())
}

/// Generate packet metadata from flows and into a vector
pub fn run_vec(generator: impl Stage3, vec_s3: Vec<SeededData<Flow>>) -> S3Vector {
    log::trace!("Start S3 (vec) with {} elements", vec_s3.len());
    let mut vectors = S3Vector {
        tcp: Vec::with_capacity(
            vec_s3
                .iter()
                .filter(|f| matches!(f.data, Flow::Tcp(_, _)))
                .count(),
        ),
        udp: Vec::with_capacity(
            vec_s3
                .iter()
                .filter(|f| matches!(f.data, Flow::Udp(_)))
                .count(),
        ),
        icmp: Vec::with_capacity(
            vec_s3
                .iter()
                .filter(|f| matches!(f.data, Flow::Icmp(_)))
                .count(),
        ),
    };
    for flow in vec_s3 {
        log::trace!("Generating packets info");
        match flow.data {
            Flow::Tcp(data, conn_state) => {
                if let Some(pir) = generator.generate_tcp_packets_info(
                    SeededData {
                        seed: flow.seed,
                        data,
                    },
                    conn_state,
                ) {
                    vectors.tcp.push(pir);
                }
            }
            Flow::Udp(data) => {
                if let Some(pir) = generator.generate_udp_packets_info(SeededData {
                    seed: flow.seed,
                    data,
                }) {
                    vectors.udp.push(pir);
                }
            }
            Flow::Icmp(data) => {
                if let Some(pir) = generator.generate_icmp_packets_info(SeededData {
                    seed: flow.seed,
                    data,
                }) {
                    vectors.icmp.push(pir);
                }
            }
        }
    }
    log::trace!("S3 stops");
    vectors
}
