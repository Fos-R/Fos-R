use crate::stage1::*;
use rand_distr::weighted::WeightedIndex;
use rand_distr::{Distribution, Uniform};
use rand_pcg::Pcg32;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs::File;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;
use std::iter;

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
    proto: Option<Protocol>,
    // tcp_flags: Option<TCPEndFlags>,
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
        };
        // match p.proto.unwrap() {
        //     Protocol::TCP => Flow::TCP(d, p.tcp_flags.unwrap()),
        //     Protocol::UDP => Flow::UDP(d),
        //     Protocol::ICMP => Flow::ICMP(d),
        // }
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
            Feature::Duration(_) => (),
            Feature::Proto(v) => self.proto = Some(v[0]),
            Feature::Flags(_) => (),
        }
    }
}

/// A node of the Bayesian network
#[derive(Deserialize, Debug, Clone)]
struct BayesianNetworkNode {
    feature: Feature,
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
                .map(|(low, high)| Uniform::new(low, high).unwrap()) // TODO: uniform ?
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
    // FwdByt(Intervals),
    // BwdByt(Intervals),
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

#[derive(Deserialize, Debug)]
struct BayesianNetwork(Vec<BayesianNetworkNode>);

impl BayesianNetwork {
    /// Sample a vector from the Bayesian network
    fn sample(
        &self,
        rng: &mut impl RngCore,
    ) -> PartiallyDefinedFlowData {
        let uniform = Uniform::new(32000, 65535).unwrap();
        let mut indices = Vec::with_capacity(self.0.len());
        let mut p = PartiallyDefinedFlowData::default();
        for v in self.0.iter() {
            let i = v.sample_index(rng, &indices);
            indices.push(i);
            p.set_value(rng, &v.feature, i);
        }
        p.src_port = Some(uniform.sample(rng) as u16);
        p
    }

}

#[derive(Deserialize, Debug)]
pub struct BayesianModel {
    bn: BayesianNetwork, // the empty pattern is considered to be a pattern like the others
    metadata: BNMetaData,
}

// TODO: add again when the file is written
// impl Default for BayesianModel {
//     #[cfg(debug_assertions)]
//     fn default() -> Self {
//         let set: BayesianModel =
//             serde_json::from_str(include_str!("../../default_models/bayesian_model.json"))
//                 .unwrap();
//         set
//     }

//     #[cfg(not(debug_assertions))]
//     fn default() -> Self {
//         let set: BayesianModel = serde_json::from_str(
//             &String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
//                 "default_models/bayesian_model.json",
//                 19
//             ))
//             .unwrap(),
//         )
//         .unwrap();
//         set
//     }
// }

impl BayesianModel {
    /// Import patterns from a file
    pub fn from_file(filename: &str) -> std::io::Result<Self> {
        log::info!("Loading patterns…");
        let f = File::open(filename)?;
        let set: BayesianModel = serde_json::from_reader(f)?;
        log::info!("Bayesian model loaded from {filename:?}");
        Ok(set)
    }
}

#[derive(Deserialize, Debug, Clone)]
#[allow(unused)]
struct BNMetaData {
    input_file: String,
    creation_time: String,
}

/// Stage 1: generates flow descriptions
#[derive(Clone)]
#[allow(unused)]
pub struct BNGenerator {
    model: Arc<BayesianModel>,
    config: Hosts,
    online: bool, // used to generate the TTL, either initial or at the capture point
}

impl BNGenerator {
    pub fn new(model: Arc<BayesianModel>, config: Hosts, online: bool) -> Self {
        // TODO: adapter le modèle à la config !
        BNGenerator {
            model,
            config,
            online,
        }
    }
}

impl Stage1 for BNGenerator {
    /// Generates flows
    fn generate_flows(&self, ts: SeededData<Duration>) -> impl Iterator<Item = SeededData<Flow>> {
        let mut rng = Pcg32::seed_from_u64(ts.seed);
        let mut data: PartiallyDefinedFlowData = self.model.bn.sample(&mut rng);
        data.timestamp = Some(ts.data);
        data.ttl_client = Some(self.config.get_default_ttl(&data.src_ip.unwrap()));
        data.ttl_server = Some(self.config.get_default_ttl(&data.dst_ip.unwrap()));
        iter::once(SeededData {
            seed: rng.next_u64(),
            data: data.into() })
    }
}
