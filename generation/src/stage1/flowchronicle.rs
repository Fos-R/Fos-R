#![allow(unused)]

use crate::structs::*;
use crate::stage1::*;
use serde::Deserialize;
use std::fs::File;
use rand_pcg::Pcg32;
use rand::prelude::*;
use std::time::Duration;
use std::sync::Arc;
use std::net::Ipv4Addr;
use std::collections::HashMap;
use rand::distributions::WeightedIndex;
use rand::distributions::Uniform;

#[derive(Debug, Clone)]
struct PartiallyDefinedFlowData {
    src_ip: Option<Ipv4Addr>,
    dst_ip: Option<Ipv4Addr>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    ttl_client: Option<u8>,
    ttl_server: Option<u8>,
    fwd_packets_count: Option<u32>,
    bwd_packets_count: Option<u32>,
    fwd_total_payload_length: Option<u32>,
    bwd_total_payload_length: Option<u32>,
    timestamp: Option<Duration>,
    total_duration: Option<Duration>,
    proto: Option<Protocol>,
}

impl PartiallyDefinedFlowData {

    fn into_flow(self) -> Flow {
        let d = FlowData {
            src_ip: self.src_ip.unwrap(),
            dst_ip: self.dst_ip.unwrap(),
            src_port: self.src_port.unwrap(),
            dst_port: self.dst_port.unwrap(),
            ttl_client: self.ttl_client.unwrap(),
            ttl_server: self.ttl_server.unwrap(),
            fwd_packets_count: self.fwd_packets_count.unwrap(),
            bwd_packets_count: self.bwd_packets_count.unwrap(),
            fwd_total_payload_length: self.fwd_total_payload_length.unwrap(),
            bwd_total_payload_length: self.bwd_total_payload_length.unwrap(),
            timestamp: self.timestamp.unwrap(),
            total_duration: self.total_duration.unwrap(),
        };
        match self.proto.unwrap() {
            Protocol::TCP => Flow::TCP(d),
            Protocol::UDP => Flow::UDP(d),
            Protocol::ICMP => Flow::ICMP(d),
        }
    }

    fn set_value(&mut self, rng: &mut Pcg32, f: &Feature, index: usize) {
        match f {
            Feature::SrcIP(ref v) => self.src_ip = Some(v.0[index]),
            Feature::DstIP(ref v) => self.dst_ip = Some(v.0[index]),
            Feature::FwdPkt(ref v) => self.fwd_packets_count = Some(v.0[index].sample(rng)),
            Feature::BwdPkt(ref v) => self.bwd_packets_count = Some(v.0[index].sample(rng)),
            Feature::FwdByt(ref v) => self.fwd_total_payload_length = Some(v.0[index].sample(rng)),
            Feature::BwdByt(ref v) => self.bwd_total_payload_length = Some(v.0[index].sample(rng)),
            Feature::Proto(ref v) => self.proto = Some(v.clone()),
        }
    }
}


#[derive(Deserialize, Debug, Clone)]
enum Protocol {
    TCP,
    UDP,
    ICMP,
}

/// A node of the Bayesian network
#[derive(Deserialize, Debug, Clone)]
struct BayesianNetworkNode {
    feature: Feature,
    partial_flow_number: usize,
    parents: Vec<usize>, // indices in the Bayesian network’s nodes
    cpt: Vec<CptLine>
}

#[derive(Deserialize, Debug, Clone)]
#[serde(from = "Vec<String>")]
struct Ipv4Vector(Vec<Ipv4Addr>);

impl From<Vec<String>> for Ipv4Vector {
    fn from(v: Vec<String>) -> Ipv4Vector {
        // TODO: et les IP publiques anonymisées ?
        Ipv4Vector(v.into_iter().map(|s| s.parse().unwrap()).collect())
    }
}

#[derive(Deserialize, Debug, Clone)]
#[serde(from = "Vec<(u32,u32)>")]
struct Intervals(Vec<Uniform<u32>>);

impl From<Vec<(u32,u32)>> for Intervals {
    fn from(v: Vec<(u32,u32)>) -> Intervals {
        Intervals(v.into_iter().map(|(low,high)| Uniform::new(low, high)).collect())
    }
}

#[derive(Deserialize, Debug, Clone)]
#[serde(tag = "type", content = "domain")]
enum Feature {
    SrcIP(Ipv4Vector),
    DstIP(Ipv4Vector),
    FwdPkt(Intervals),
    BwdPkt(Intervals),
    FwdByt(Intervals),
    BwdByt(Intervals),
    Proto(Protocol)
}

#[derive(Deserialize, Debug, Clone)]
struct CptLineJSON {
    probas: Vec<Vec<f32>>,
    parents_values: Vec<Vec<u32>>
}

#[derive(Deserialize, Debug, Clone)]
#[serde(from = "CptLineJSON")]
struct CptLine(HashMap<Vec<u32>,WeightedIndex<f32>>);

impl CptLine {
    fn sample(&self, rng: &mut Pcg32, parents_values: &Vec<u32>) -> usize {
        self.0[parents_values].sample(rng)
    }
}

impl From<CptLineJSON> for CptLine {
    fn from(line: CptLineJSON) -> CptLine {
        let mut cptline = HashMap::new();
        let mut iter_probas = line.probas.into_iter();
        for v in line.parents_values.into_iter() {
            cptline.insert(v, WeightedIndex::new(iter_probas.next().unwrap()).unwrap());
        }
        CptLine(cptline)
    }
}

impl BayesianNetworkNode {
    /// Sample the value of one variable and update the vector with it
    fn sample_index(&self, rng: &mut Pcg32) -> usize {
        todo!()
    }
}

/// The possible values of the cells inside a pattern
#[derive(Deserialize, Debug, Clone)]
#[serde(tag = "type")]
enum CellType {
    Fixed { feature: Feature }, // only one value in the Feature domain
    ReuseSrcAsSrc { row: usize }, // reuse the IP from that row
    ReuseSrcAsDst { row: usize },
    ReuseDrcAsSrc { row: usize },
    ReuseDrcAsDst { row: usize },
}

#[derive(Deserialize, Debug, Clone)]
struct BayesianNetwork {
    graph: Vec<BayesianNetworkNode>, // order is assumed to be topological
}

impl BayesianNetwork {
    /// Sample a vector from the Bayesian network
    fn sample_free_cells(&self, rng: &mut Pcg32, flow_count: usize) -> Vec<PartiallyDefinedFlowData> {
        let mut p = PartiallyDefinedFlowData { src_ip: None, dst_ip: None, src_port: None, dst_port: None,
            ttl_client: None, ttl_server: None,
            fwd_packets_count: None,
            bwd_packets_count: None,
            fwd_total_payload_length: None,
            bwd_total_payload_length: None,
            timestamp: None, total_duration: None,
            proto: None, };

        for v in self.graph.iter() {
            let i = v.sample_index(rng);
            p.set_value(rng, &v.feature, i);
        }
        todo!()
    }

}

#[derive(Deserialize, Debug, Clone)]
struct PartialFlowRow {
    time_distrib: f32, // either the starting timestamp distribution or the IAT distribution
    row: Vec<CellType>
}

/// Each pattern has partial flows and a Bayesian network that describes the distribution of "free" cells
#[derive(Deserialize, Debug, Clone)]
struct Pattern {
    weight: u32,
    partial_flows: Vec<PartialFlowRow>,
    bayesian_network: BayesianNetwork,
}

impl Pattern {
    /// Sample flows
    fn sample(&self, rng: &mut Pcg32, ts: Duration) -> Vec<Flow> {
        let mut partially_defined_flows = self.bayesian_network.sample_free_cells(rng, self.partial_flows.len());
        for (r_index,p) in self.partial_flows.iter().enumerate() {
            partially_defined_flows.get_mut(r_index).unwrap().timestamp = Some(ts); // TODO tirage
            for (c_index,c) in p.row.iter().enumerate() {
                match c {
                    CellType::ReuseSrcAsSrc{ row } => { partially_defined_flows.get_mut(r_index).unwrap().src_ip = partially_defined_flows[*row].src_ip },
                    CellType::ReuseSrcAsDst{ row } => { partially_defined_flows.get_mut(r_index).unwrap().dst_ip = partially_defined_flows[*row].src_ip },
                    CellType::ReuseDrcAsSrc{ row } => { partially_defined_flows.get_mut(r_index).unwrap().src_ip = partially_defined_flows[*row].dst_ip },
                    CellType::ReuseDrcAsDst{ row } => { partially_defined_flows.get_mut(r_index).unwrap().dst_ip = partially_defined_flows[*row].dst_ip },
                    CellType::Fixed{ feature } => partially_defined_flows.get_mut(r_index).unwrap().set_value(rng, feature, 0),
                };
            }
        }
        partially_defined_flows.into_iter().map(PartiallyDefinedFlowData::into_flow).collect()
    }

}

#[derive(Deserialize, Debug, Clone)]
pub struct PatternSet {
    patterns: Vec<Pattern>, // the empty pattern is considered to be a pattern like the others
    metadata: PatternMetaData,
}

impl PatternSet {
    pub fn merge(&mut self, other: PatternSet, weight: Option<f64>) {
        todo!()
    }

    /// Import patterns from a file
    pub fn from_file(filename: &str) -> std::io::Result<Self> {
        Ok(PatternSet { patterns: vec![], metadata: PatternMetaData { input_file: "".to_string(), creation_time: "".to_string() } }) // TODO

        // let f = File::open(filename)?;
        // let set : PatternSet = serde_json::from_reader(f)?;
        // log::info!("Patterns loaded from {:?}",filename);
        // Ok(set)
    }

    /// Import patterns from a file
    pub fn from_str(data: &str) -> std::io::Result<Self> {
        let set : PatternSet = serde_json::from_str(data)?;
        log::info!("Default patterns loaded");
        Ok(set)
    }
}

#[derive(Deserialize, Debug, Clone)]
struct PatternMetaData {
    input_file: String,
    creation_time: String,
}

/// Stage 1: generates flow descriptions
pub struct FCGenerator {
    set: Arc<PatternSet>,
    online: bool, // used to generate the TTL, either initial or at the capture point
}


impl FCGenerator {
    pub fn new(patterns: Arc<PatternSet>, online: bool) -> Self {
        FCGenerator { set: patterns, online }
    }
}

impl Stage1 for FCGenerator {

    // /// Generates flows
    // pub fn generate_flows2(&self, ts: SeededData<Duration>) -> Vec<SeededData<Flow>> {
    //     let mut rng = Pcg32::seed_from_u64(ts.seed);
    //     // select pattern TODO
    //     let pattern = &self.set.patterns[0];
    //     // TODO
    //     pattern.sample(&mut rng, ts.data).into_iter().map(|f| SeededData { seed: rng.next_u64(), data: f }).collect()
    // }

    /// Placeholder
    fn generate_flows(&self, ts: SeededData<Duration>) -> Vec<SeededData<Flow>> {
        let mut rng = Pcg32::seed_from_u64(ts.seed);
        let flow = Flow::TCP(FlowData {
            src_ip: Ipv4Addr::new(192, 168, 1, 8),
            dst_ip: Ipv4Addr::new(192, 168, 1, 14),
            src_port: 34200,
            dst_port: 21,
            ttl_client: 23,
            ttl_server: 68,
            fwd_packets_count: 3,
            bwd_packets_count: 2,
            fwd_total_payload_length: 122,
            bwd_total_payload_length: 88,
            timestamp: ts.data,
            total_duration: Duration::from_millis(2300),
            } );
        vec![SeededData { seed: rng.next_u64(), data: flow }] // TODO
    }

}

