use crate::stage1::*;
use rand_distr::Uniform;
use rand_distr::{Distribution, WeightedIndex};
use rand_pcg::Pcg32;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs::File;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, Default)]
struct PartiallyDefinedFlowData {
    src_ip: Option<Ipv4Addr>,
    dst_ip: Option<Ipv4Addr>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    ttl_client: Option<u8>,
    ttl_server: Option<u8>,
    fwd_packets_count: Option<usize>,
    bwd_packets_count: Option<usize>,
    timestamp: Option<Duration>,
    // total_duration: Option<Duration>,
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
            fwd_packets_count: p.fwd_packets_count,
            bwd_packets_count: p.bwd_packets_count,
            timestamp: p.timestamp.unwrap(),
            // total_duration: p.total_duration.unwrap(),
        };
        p.proto.unwrap().wrap(d)
    }
}

impl PartiallyDefinedFlowData {
    fn set_value(&mut self, rng: &mut impl RngCore, f: &Feature, index: usize) {
        match f {
            Feature::SrcIP(v) => self.src_ip = Some(v.0[index]),
            Feature::DstIP(v) => self.dst_ip = Some(v.0[index]),
            Feature::DstPt(v) => self.dst_port = Some(v[index]),
            Feature::FwdPkt(v) => self.fwd_packets_count = Some(v.0[index].sample(rng) as usize),
            Feature::BwdPkt(v) => self.bwd_packets_count = Some(v.0[index].sample(rng) as usize),
            Feature::FwdByt(_) => (), // ignore
            Feature::BwdByt(_) => (), // ignore
            Feature::Duration(_) => (),
            //                self.total_duration = Some(Duration::from_millis(v.0[index].sample(rng) as u64))
            Feature::Proto(v) => self.proto = Some(v[0]),
            Feature::Flags(_) => (),
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
#[serde(from = "Vec<(u64,u64)>")]
struct Intervals(Vec<Uniform<u64>>);

impl From<Vec<(u64, u64)>> for Intervals {
    fn from(v: Vec<(u64, u64)>) -> Intervals {
        Intervals(
            v.into_iter()
                .map(|(low, high)| Uniform::new(low, high))
                .collect(),
        )
    }
}

#[derive(Deserialize, Debug, Clone)]
#[serde(tag = "type", content = "domain")]
#[allow(unused)]
enum Feature {
    SrcIP(Ipv4Vector),
    DstIP(Ipv4Vector),
    DstPt(Vec<u16>),
    FwdPkt(Intervals),
    BwdPkt(Intervals),
    FwdByt(Intervals),
    BwdByt(Intervals),
    Proto(Vec<Protocol>),
    Duration(Vec<(f64, f64)>),
    Flags(Vec<String>),
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
        // TODO: mettre dans la structure pour ne pas allouer à chaque fois
        let parents_values: Vec<usize> = self.parents.iter().map(|p| current[*p]).collect();
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
    SrcIpScenario,
    DstIpScenario,
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
        for v in self.bayesian_network.iter() {
            let i = v.sample_index(rng, &indices);
            indices.push(i);
            p[v.partial_flow_number].set_value(rng, &v.feature, i);
        }
        p
    }
}

/// Each pattern has partial flows and a Bayesian network that describes the distribution of "free" cells
#[derive(Deserialize, Debug, Clone)]
struct Pattern {
    // TODO: add time distribution
    partial_flows: Vec<Vec<CellType>>,
    bayesian_network: Vec<BayesianNetworkNode>,
}

impl Pattern {
    /// Sample flows
    fn sample(&self, rng: &mut impl RngCore, config: &Hosts, ts: Duration) -> Vec<Flow> {
        loop {
            // First, sample all the free cells
            let mut partially_defined_flows = self.sample_free_cells(rng, self.partial_flows.len());
            // Sample source port
            for p in partially_defined_flows.iter_mut() {
                p.src_port = Some(Uniform::new(32000, 65535).sample(rng) as u16);
            }
            // Complete with reused Placeholder and fixed values
            let mut current_ts = ts;
            for (r_index, p) in self.partial_flows.iter().enumerate() {
                partially_defined_flows.get_mut(r_index).unwrap().timestamp = Some(current_ts);
                // TODO tirage
                current_ts += Duration::from_millis(500);
                for c in p.iter() {
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
                        _ => (),
                    };
                }
            }
            let mut restart = false;
            // Complete with scenario dependent values
            for p in partially_defined_flows.iter_mut() {
                // TODO: gérer les cas où seuls l’un deux est None
                if p.src_ip.is_none() && p.dst_ip.is_none() {
                    if let Some((src_ip, dst_ip)) =
                        config.get_src_and_dst_ip(rng, p.dst_port.unwrap())
                    {
                        p.src_ip = Some(src_ip);
                        p.dst_ip = Some(dst_ip);
                    } else {
                        log::warn!(
                            "No provider or user IP for dst port {}",
                            p.dst_port.unwrap()
                        );
                        restart = true;
                        break; // start again
                    }
                }
                p.ttl_client = Some(config.get_default_ttl(&p.src_ip.unwrap()));
                p.ttl_server = Some(config.get_default_ttl(&p.dst_ip.unwrap()));
            }
            if restart {
                thread::sleep(Duration::from_millis(1));
                continue;
            }
            return partially_defined_flows
                .into_iter()
                .map(|p| p.into())
                .collect();
        }
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
#[allow(unused)]
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
    #[cfg(debug_assertions)]
    fn default() -> Self {
        let set: PatternSet =
            serde_json::from_str(include_str!("../../breizhctf-patterns.json")).unwrap();
        set
    }

    #[cfg(not(debug_assertions))]
    fn default() -> Self {
        let set: PatternSet = serde_json::from_str(
            &String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                "breizhctf-patterns.json",
                19
            ))
            .unwrap(),
        )
        .unwrap();
        set
    }
}

impl PatternSet {
    // pub fn merge(&mut self, other: PatternSet, weight: Option<f64>) {
    //     todo!()
    // }

    /// Import patterns from a file
    pub fn from_file(filename: &str) -> std::io::Result<Self> {
        log::info!("Loading patterns…");
        let f = File::open(filename)?;
        let set: PatternSet = serde_json::from_reader(f)?;
        log::info!("Patterns loaded from {:?}", filename);
        Ok(set)
    }
}

#[derive(Deserialize, Debug, Clone)]
#[allow(unused)]
struct PatternMetaData {
    input_file: String,
    creation_time: String,
}

/// Stage 1: generates flow descriptions
#[derive(Clone)]
#[allow(unused)]
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
        let p = pattern.sample(&mut rng, &self.config, ts.data);
        p.into_iter().map(move |f| SeededData {
            seed: rng.next_u64(),
            data: f,
        })
    }
}
