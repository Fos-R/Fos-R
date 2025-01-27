#![allow(unused)]

use crate::stage1::*;
use crate::structs::*;
use rand_distr::Uniform;
use rand_distr::{Distribution, WeightedIndex};
use rand_pcg::Pcg32;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs::File;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, Default)]
struct PartiallyDefinedFlowData {
    src_ip: Option<Ipv4Addr>,
    dst_ip: Option<Ipv4Addr>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    ttl_client: Option<u8>,
    ttl_server: Option<u8>,
    fwd_packets_count: Option<u32>,
    bwd_packets_count: Option<u32>,
    timestamp: Option<Duration>,
    total_duration: Option<Duration>,
    proto: Option<Protocol>,
}

impl From<PartiallyDefinedFlowData> for Flow {
    fn from(p: PartiallyDefinedFlowData) -> Self {
        let d = FlowData {
            src_ip: p.src_ip.unwrap(),
            dst_ip: p.dst_ip.unwrap(),
            src_port: p.src_port.unwrap(),
            dst_port: p.dst_port.unwrap(),
            ttl_client: p.ttl_client.unwrap(),
            ttl_server: p.ttl_server.unwrap(),
            fwd_packets_count: p.fwd_packets_count.unwrap() as usize,
            bwd_packets_count: p.bwd_packets_count.unwrap() as usize,
            timestamp: p.timestamp.unwrap(),
            total_duration: p.total_duration.unwrap(),
        };
        p.proto.unwrap().wrap(d)
    }
}

impl PartiallyDefinedFlowData {
    fn set_value(&mut self, rng: &mut impl RngCore, f: &Feature, index: usize) {
        match f {
            Feature::SrcIP(ref v) => self.src_ip = Some(v.0[index]),
            Feature::DstIP(ref v) => self.dst_ip = Some(v.0[index]),
            Feature::DstPt(ref v) => self.dst_port = Some(v.0[index].sample(rng) as u16),
            Feature::FwdPkt(ref v) => self.fwd_packets_count = Some(v.0[index].sample(rng)),
            Feature::BwdPkt(ref v) => self.bwd_packets_count = Some(v.0[index].sample(rng)),
            Feature::FwdByt(ref v) => (), // ignore
            Feature::BwdByt(ref v) => (), // ignore
            Feature::Duration(ref v) => {
                self.total_duration = Some(Duration::from_millis(v.0[index].sample(rng) as u64))
            }
            Feature::Proto(ref v) => self.proto = Some(v[0]),
        }
    }
}

/// A node of the Bayesian network
#[derive(Deserialize, Debug, Clone)]
struct BayesianNetworkNode {
    feature: Feature,
    partial_flow_number: usize,
    parents: Vec<usize>, // indices in the Bayesian network’s nodes
    cpt: CPT,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(from = "Vec<String>")]
struct Ipv4Vector(Vec<Ipv4Addr>);

impl From<Vec<String>> for Ipv4Vector {
    fn from(v: Vec<String>) -> Ipv4Vector {
        // ignore non-IPv4, like anonymised public IP addresses
        Ipv4Vector(v.into_iter().flat_map(|s| s.parse()).collect())
    }
}

#[derive(Deserialize, Debug, Clone)]
#[serde(from = "Vec<(u32,u32)>")]
struct Intervals(Vec<Uniform<u32>>);

impl From<Vec<(u32, u32)>> for Intervals {
    fn from(v: Vec<(u32, u32)>) -> Intervals {
        Intervals(
            v.into_iter()
                .map(|(low, high)| Uniform::new(low, high))
                .collect(),
        )
    }
}

#[derive(Deserialize, Debug, Clone)]
#[serde(tag = "type", content = "domain")]
enum Feature {
    SrcIP(Ipv4Vector),
    DstIP(Ipv4Vector),
    DstPt(Intervals),
    FwdPkt(Intervals),
    BwdPkt(Intervals),
    FwdByt(Intervals),
    BwdByt(Intervals),
    Proto(Vec<Protocol>),
    Duration(Intervals),
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Deserialize, Debug, Clone)]
struct CPTJSON {
    probas: Vec<Vec<f32>>,
    parents_values: Vec<Vec<usize>>,
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Deserialize, Debug, Clone)]
#[serde(from = "CPTJSON")]
struct CPT(HashMap<Vec<usize>, WeightedIndex<f32>>);

impl From<CPTJSON> for CPT {
    fn from(line: CPTJSON) -> CPT {
        assert_eq!(line.probas.len(), line.parents_values.len());
        let mut cpt = HashMap::new();
        let mut iter_probas = line.probas.into_iter();
        for v in line.parents_values {
            cpt.insert(v, WeightedIndex::new(iter_probas.next().unwrap()).unwrap());
        }
        CPT(cpt)
        // TODO projeter les IP sur la configuration ?
    }
}

impl BayesianNetworkNode {
    /// Sample the value of one variable and update the vector with it
    fn sample_index(&self, rng: &mut impl RngCore, current: &[usize]) -> usize {
        let mut parents_values = Vec::new();
        for (i, p) in self.parents.iter().enumerate() {
            parents_values[i] = current[*p];
        }
        self.cpt.0[&parents_values].sample(rng)
    }
}

/// The possible values of the cells inside a pattern
#[derive(Deserialize, Debug, Clone)]
#[serde(tag = "type")]
enum CellType {
    Fixed { feature: Feature },   // only one value in the Feature domain
    ReuseSrcAsSrc { row: usize }, // reuse the IP from that row
    ReuseSrcAsDst { row: usize },
    ReuseDrcAsSrc { row: usize },
    ReuseDrcAsDst { row: usize },
}

impl Pattern {
    /// Sample a vector from the Bayesian network
    fn sample_free_cells(
        &self,
        rng: &mut impl RngCore,
        flow_count: usize,
    ) -> Vec<PartiallyDefinedFlowData> {
        let mut p = Vec::new();
        let mut indices = Vec::with_capacity(self.bayesian_network.len());
        for _ in 0..flow_count {
            p.push(PartiallyDefinedFlowData::default());
        }
        for (n, v) in self.bayesian_network.iter().enumerate() {
            let i = v.sample_index(rng, &indices);
            indices[n] = i;
            p[v.partial_flow_number].set_value(rng, &v.feature, i);
        }
        p
    }
}

#[derive(Deserialize, Debug, Clone)]
struct PartialFlowRow {
    row: Vec<CellType>,
}

/// Each pattern has partial flows and a Bayesian network that describes the distribution of "free" cells
#[derive(Deserialize, Debug, Clone)]
struct Pattern {
    // TODO: add time distribution
    partial_flows: Vec<PartialFlowRow>,
    bayesian_network: Vec<BayesianNetworkNode>,
}

impl Pattern {
    /// Sample flows
    fn sample(&self, rng: &mut impl RngCore, config: &Hosts, ts: Duration) -> impl Iterator<Item = Flow> {
        let mut partially_defined_flows = self.sample_free_cells(rng, self.partial_flows.len());
        for p in partially_defined_flows.iter_mut() {
            p.src_port = Some(Uniform::new(32000, 65535).sample(rng) as u16);
        }
        for (r_index, p) in self.partial_flows.iter().enumerate() {
            partially_defined_flows.get_mut(r_index).unwrap().timestamp = Some(ts); // TODO tirage
            for (c_index, c) in p.row.iter().enumerate() {
                match c {
                    CellType::ReuseSrcAsSrc { row } => {
                        partially_defined_flows.get_mut(r_index).unwrap().src_ip =
                            partially_defined_flows[*row].src_ip
                    }
                    CellType::ReuseSrcAsDst { row } => {
                        partially_defined_flows.get_mut(r_index).unwrap().dst_ip =
                            partially_defined_flows[*row].src_ip
                    }
                    CellType::ReuseDrcAsSrc { row } => {
                        partially_defined_flows.get_mut(r_index).unwrap().src_ip =
                            partially_defined_flows[*row].dst_ip
                    }
                    CellType::ReuseDrcAsDst { row } => {
                        partially_defined_flows.get_mut(r_index).unwrap().dst_ip =
                            partially_defined_flows[*row].dst_ip
                    }
                    CellType::Fixed { feature } => partially_defined_flows
                        .get_mut(r_index)
                        .unwrap()
                        .set_value(rng, feature, 0),
                };
            }
        }
        for p in partially_defined_flows.iter_mut() {
            p.ttl_client = config.get_default_ttl(&p.src_ip.unwrap());
            p.ttl_server = config.get_default_ttl(&p.dst_ip.unwrap());
        }
        partially_defined_flows.into_iter().map(|p| p.into())
    }
}

#[derive(Deserialize, Debug)]
pub struct PatternSetJSON {
    patterns: Vec<Pattern>, // the empty pattern is considered to be a pattern like the others
    metadata: PatternMetaData,
    pattern_weights: Vec<u32>,
}

#[derive(Deserialize, Debug)]
#[serde(from = "PatternSetJSON")]
pub struct PatternSet {
    patterns: Vec<Pattern>, // the empty pattern is considered to be a pattern like the others
    pattern_distrib: WeightedIndex<u32>, // constructed from the weight
    metadata: PatternMetaData,
}

impl From<PatternSetJSON> for PatternSet {
    fn from(p: PatternSetJSON) -> PatternSet {
        let pattern_distrib = WeightedIndex::new(p.pattern_weights).unwrap();
        PatternSet {
            patterns: p.patterns,
            metadata: p.metadata,
            pattern_distrib,
        }
    }
}

impl Default for PatternSet {
    fn default() -> Self {
        let set: PatternSet =
            serde_json::from_str(include_str!("../../../models/medium/patterns.json")).unwrap();
        log::info!("Default patterns loaded");
        set
    }
}

impl PatternSet {
    pub fn merge(&mut self, other: PatternSet, weight: Option<f64>) {
        todo!()
    }

    /// Import patterns from a file
    pub fn from_file(filename: &str) -> std::io::Result<Self> {
        let f = File::open(filename)?;
        let set: PatternSet = serde_json::from_reader(f)?;
        log::info!("Patterns loaded from {:?}", filename);
        Ok(set)
    }
}

#[derive(Deserialize, Debug, Clone)]
struct PatternMetaData {
    input_file: String,
    creation_time: String,
}

/// Stage 1: generates flow descriptions
#[derive(Clone)]
pub struct FCGenerator {
    set: Arc<PatternSet>,
    config: Hosts,
    online: bool, // used to generate the TTL, either initial or at the capture point
}

impl FCGenerator {
    pub fn new(patterns: Arc<PatternSet>, config: Hosts, online: bool) -> Self {
        FCGenerator {
            set: patterns,
            config,
            online,
        }
    }
}

impl Stage1 for FCGenerator {
    /// Generates flows
    fn generate_flows(&self, ts: SeededData<Duration>) -> impl Iterator<Item = SeededData<Flow>> {
        let mut rng = Pcg32::seed_from_u64(ts.seed);
        let index = self.set.pattern_distrib.sample(&mut rng);
        let pattern = &self.set.patterns[index];
        pattern.sample(&mut rng, &self.config, ts.data).map(move |f| SeededData {
            seed: rng.next_u64(),
            data: f,
        })
    }
}
