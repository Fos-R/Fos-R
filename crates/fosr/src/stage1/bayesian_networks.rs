use crate::stage1::*;
use crate::structs::*;

use rand_distr::weighted::WeightedIndex;
use rand_distr::{Distributionè Normal};
use rand_pcg::Pcg32;
use serde::Deserialize;
use serde_xml_rs::{from_str, to_string};
use std::collections::HashMap;
use std::iter;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, Default)]
struct IntermediateVector {
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
        todo!()
        // match f {
        //     Feature::SrcIP(v) => self.src_ip = Some(v.0[index]),
        //     Feature::DstIP(v) => self.dst_ip = Some(v.0[index]),
        //     Feature::DstPt(v) => self.dst_port = Some(v[index]),
        //     Feature::FwdPkt(v) => self.fwd_packets_count = Some(v.0[index].sample(rng) as usize),
        //     Feature::BwdPkt(v) => self.bwd_packets_count = Some(v.0[index].sample(rng) as usize),
        //     Feature::Duration(_) => (),
        //     Feature::L4Proto(v) => self.proto = Some(v[0]),
        //     Feature::Flags(_) => (),
        //     _ => todo!(),
        // }
    }
}

/// A node of the Bayesian network
#[derive(Debug, Clone)]
struct BayesianNetworkNode {
    index: usize, // overall index, unique across the several BNs
    feature: Feature,
    parents: Vec<usize>, // indices in the Bayesian network’s nodes
}

enum L7Proto {
    HTTP,
    HTTPS,
    SSH,
// TODO complete
}

impl L7Proto {
    fn default_port(&self) -> u16 {
        todo!()
    }
}


#[derive(Debug, Clone)]
enum Feature {
    // for each feature, we associate a domain and a discrete probability distribution (when sample
    // by the bayesian network)
    TimeBin, // never sampled, so no CPT
    SrcIpRole(CPT, Vec<String>),
    DstIpRole(CPT, Vec<String>),
    SrcIp(CPT, Vec<Ipv4Addr>),  // the IP comes from the config
    DstIp(CPT, Vec<Ipv4Addr>),  // the IP comes from the config
    DstPt(CPT, Vec<u16>),    // the port comes from the config (must be chosen after the dest IP)
    FwdPkt(CPT, Vec<Normal>),  // the exact number is sampled from a Gaussian distribution afterward
    BwdPkt(CPT, Vec<Normal>), // idem
    L7Proto(CPT, Vec<String>),
    L4Proto(CPT, Vec<Protocol>),
    EndFlags(CPT, Vec<TCPEndFlags>),
}



// impl From<Vec<String>> for Ipv4Vector {
//     fn from(v: Vec<String>) -> Ipv4Vector {
//         // ignore non-IPv4, like anonymised public IP addresses
//         Ipv4Vector(v.into_iter().flat_map(|s| s.parse()).collect())
//     }
// }

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone)]
struct CPT(HashMap<Vec<usize>, WeightedIndex<f32>>);

impl BayesianNetworkNode {
    /// Sample the value of one variable and update the vector with it
    fn sample_index(&self, rng: &mut impl RngCore, current: &[usize]) -> usize {
        // TODO: mettre dans la structure pour ne pas allouer à chaque fois
        let parents_values: Vec<usize> = self.parents.iter().map(|p| current[*p]).collect();
        self.cpt.0[&parents_values].sample(rng)
    }
}

#[derive(Debug)]
struct BayesianNetwork(Vec<BayesianNetworkNode>);

impl BayesianNetwork {
    /// Sample a vector from the Bayesian network
    fn sample(&self, rng: &mut impl RngCore, partial_vector: &mut PartiallyDefinedFlowData) {
        // TODO: use smallvec for indices
        let mut indices = Vec::with_capacity(self.0.len());
        // let mut p = PartiallyDefinedFlowData::default();
        for v in self.0.iter() {
            let i = v.sample_index(rng, &indices);
            indices.push(i);
            partial_vector.set_value(rng, &v.feature, i);
        }
        // p.src_port = Some(uniform.sample(rng) as u16);
        // p
    }
}

// BIFXML format

#[derive(Deserialize, Debug)]
#[serde(rename_all = "UPPERCASE")]
pub struct Bif {
    network: Network,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "UPPERCASE")]
pub struct Network {
    name: String, // TODO paramétrer dans agrum
    property: String, // learning software
    variable: Vec<Variable>, // TODO: est-on sûr que c’est dans l’ordre topologique ? est-on sûr
                             // que les variables sont dans le même ordre entre "variable" et
                             // "definition" ?
    definition: Vec<Definition>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "UPPERCASE")]
pub struct Variable {
    name: String,
    property: Vec<String>,
    outcome: Vec<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "UPPERCASE")]
pub struct Definition {
    #[serde(rename = "FOR")]
    variable: String,
    given: Vec<String>,
    table: String,
}

/// Stage 1: generates flow descriptions
#[derive(Clone)]
#[allow(unused)]
pub struct BNGenerator {
    // model: Arc<BayesianModel>,
    config: Hosts,
    online: bool, // used to generate the TTL, either initial or at the capture point
}

#[derive(Deserialize, Debug, Clone)]
struct AdditionalData {
    s0_bin_count: u64,
    ttl: HashMap<String, u64>,
    tcp_out_pkt_gaussians: GaussianDistribs,
    tcp_in_pkt_gaussians: GaussianDistribs,
    udp_out_pkt_gaussians: GaussianDistribs,
    udp_in_pkt_gaussians: GaussianDistribs,
}

#[derive(Deserialize, Debug, Clone)]
struct GaussianDistribs {
    mu: Vec<f64>,
    cov: Vec<f64>,
}

impl BNGenerator {
    pub fn test() {
        let bn_common: Bif = serde_xml_rs::from_str(include_str!("../../default_models/bn/bn_common.bifxml")).unwrap();
        let mut processed_bn_common = BayesianNetwork(vec![]);
        let mut overall_index: usize = 0; // common index across the BNs
        let mut name_to_index: HashMap<String, usize> = HashMap::new();
        for (index,v) in bn_common.network.variable.iter().enumerate() {
            let def = bn_common.network.definition[index];
            assert_eq!(v.name, def.variable); // we assume the order is the same between
                                                // <variable> and <definition>
            name_to_index.insert(v.name, overall_index);
            let parents = def.given.into_iter().map(|v| *name_to_index.get(&v).expect("Variable not in topological order!")).collect();
            let proba: Vec<f64> = def.table.split_ascii_whitespace().into_iter().map(|s| s.parse::<f64>().unwrap()).collect();
            for line in proba.chunks(v.outcome.len()) {
                WeightedIndex::new(line);

            }
            let cpt = todo!();
            let feature = match &v.name {
                "Time" => Feature::TimeBin,
                "Src IP Role" => Feature::SrcIpRole(cpt, v.outcome),
                "Dst IP Role" => Feature::DstIpRole(cpt, v.outcome),
                "Applicative Protocol" => Feature::L7Proto(cpt, v.outcome),
            };
            let node = BayesianNetworkNode {
                index: overall_index, // overall index, unique across the several BNs
                feature,
                parents, // indices in the Bayesian network’s nodes
                cpt: CPT,
            };
            processed_bn_common.0.push(node);
            overall_index += 1;
        }

        let bn_tcp: Bif = serde_xml_rs::from_str::<Bif>(include_str!("../../default_models/bn/bn_tcp.bifxml")).unwrap();
        let bn_udp: Bif = serde_xml_rs::from_str::<Bif>(include_str!("../../default_models/bn/bn_udp.bifxml")).unwrap();

        let bn_additional_data: AdditionalData = serde_json::from_str(include_str!("../../default_models/bn/bn_additional_data.json")).unwrap();
        log::warn!("Chargement réussi");
    }

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
    fn generate_flows(&self, ts: SeededData<TimePoint>) -> impl Iterator<Item = SeededData<Flow>> {
        let mut rng = Pcg32::seed_from_u64(ts.seed);
        let mut data: PartiallyDefinedFlowData = self.model.bn.sample(&mut rng);
        data.timestamp = Some(ts.data.unix_time); // TODO! use date_time
        data.ttl_client = Some(self.config.get_default_ttl(&data.src_ip.unwrap()));
        data.ttl_server = Some(self.config.get_default_ttl(&data.dst_ip.unwrap()));
        iter::once(SeededData {
            seed: rng.next_u64(),
            data: data.into(),
        })
    }
}
