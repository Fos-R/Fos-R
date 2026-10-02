use crate::stage2::TCPConnState;
use crate::structs::{DstIpRole, L4Proto, L7Proto, L7ProtoWithPort, OS, SrcIpRole};

use pnet::util::MacAddr;
use rand_distr::weighted::WeightedIndex;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Duration;

#[derive(Debug, Clone, Default)]
pub struct IntermediateVector {
    pub src_ip_role: Option<SrcIpRole>,
    pub dst_ip_role: Option<DstIpRole>,
    pub src_os: Option<OS>,
    pub dst_os: Option<OS>,
    pub l7_proto: Option<L7Proto>,
    pub dst_port: Option<u16>,
    pub src_port: Option<u16>,
    pub src_ttl: Option<u8>,
    pub dst_ttl: Option<u8>,
    pub packets_count_cluster: Option<usize>,
    // fwd_packets_count: Option<usize>,
    // bwd_packets_count: Option<usize>,
    pub timestamp: Option<Duration>,
    pub proto: Option<L4Proto>,
    pub tcp_flags: Option<TCPConnState>,
    pub src_ip: Option<Ipv4Addr>,
    pub dst_ip: Option<Ipv4Addr>,
    pub src_mac: Option<MacAddr>,
    pub dst_mac: Option<MacAddr>,
}

pub type AnonymizedIpv4Distr = (Vec<AnonymizedIpv4Addr>, WeightedIndex<f64>);

#[derive(Debug, Clone, Copy)]
/// An anonynized IPv4 address
/// Anonymized addresses are typically public addresses
pub enum AnonymizedIpv4Addr {
    Public,
    Known(Ipv4Addr),
}

#[derive(Debug, Clone)]
pub enum DstPt {
    Random,
    Fixed(u16),
}

#[derive(Debug, Clone)]
/// The set of random variables that can appear in a Bayesian network
pub enum Feature {
    // for each feature, we associate a domain
    TimeBin(usize), // cardinality only
    SrcIpRole(Vec<SrcIpRole>),
    DstIpRole(Vec<DstIpRole>),
    SrcOs(Vec<OS>),
    DstOs(Vec<OS>),
    SrcIp(Vec<AnonymizedIpv4Addr>), // the IP comes from the network file
    DstIp(Vec<AnonymizedIpv4Addr>), // the IP comes from the network file
    DstPt(Vec<DstPt>), // the port comes from the network file (must be chosen after the dest IP)
    PktCount(usize),   // cardinality only
    SrcTTL(Vec<u8>),
    DstTTL(Vec<u8>),
    SrcMac(Vec<MacAddr>),
    DstMac(Vec<MacAddr>),
    L7Proto(Vec<L7Proto>),
    L4Proto(Vec<L4Proto>),
    EndFlags(Vec<TCPConnState>),
}

impl Feature {
    pub fn get_value_string(&self, index: usize) -> String {
        match &self {
            // Feature::SrcIpRole(v) | Feature::DstIpRole(v) => format!("{:?}", v[index]),
            Feature::SrcIp(v) | Feature::DstIp(v) => format!("{:?}", v[index]),
            Feature::SrcOs(v) | Feature::DstOs(v) => format!("{:?}", v[index]),
            Feature::DstPt(v) => format!("{:?}", v[index]),
            Feature::PktCount(_) => format!("Cluster {index}"),
            Feature::SrcTTL(v) | Feature::DstTTL(v) => format!("{:?}", v[index]),
            Feature::SrcMac(v) | Feature::DstMac(v) => format!("{:?}", v[index]),
            Feature::L4Proto(v) => format!("{:?}", v[index]),
            Feature::L7Proto(v) => format!("{:?}", v[index]),
            Feature::EndFlags(v) => format!("{:?}", v[index]),
            Feature::TimeBin(_) => format!("Time bin {index}"),
            Feature::SrcIpRole(v) => format!("{:?}", v[index]),
            Feature::DstIpRole(v) => format!("{:?}", v[index]),
        }
    }

    pub fn get_cardinality(&self) -> usize {
        match &self {
            // Feature::SrcIpRole(v) | Feature::DstIpRole(v) => v.len(),
            Feature::SrcIp(v) | Feature::DstIp(v) => v.len(),
            Feature::SrcOs(v) | Feature::DstOs(v) => v.len(),
            Feature::DstPt(v) => v.len(),
            Feature::PktCount(card) | Feature::TimeBin(card) => *card,
            Feature::SrcTTL(v) | Feature::DstTTL(v) => v.len(),
            Feature::SrcMac(v) | Feature::DstMac(v) => v.len(),
            Feature::SrcIpRole(v) => v.len(),
            Feature::DstIpRole(v) => v.len(),
            Feature::L4Proto(v) => v.len(),
            Feature::L7Proto(v) => v.len(),
            Feature::EndFlags(v) => v.len(),
        }
    }
}

/// Extra information for the transfer learning
#[derive(Debug, Clone)]
pub struct TransferLearningExtraData {
    /// Source IP node
    pub src_ip: HashMap<(L7Proto, OS, SrcIpRole), AnonymizedIpv4Distr>,
    /// Destination IP node
    pub dst_ip: HashMap<(L7Proto, OS, DstIpRole), AnonymizedIpv4Distr>,
    /// Difference between theoretical and actual TTL observations
    pub local_ttl_delta: HashMap<Ipv4Addr, u8>,
    pub services_per_server: HashMap<(Ipv4Addr, L7Proto), Vec<L7ProtoWithPort>>,
    pub mac_addr_map: HashMap<Ipv4Addr, MacAddr>,
}
