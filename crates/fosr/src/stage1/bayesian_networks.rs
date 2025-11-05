use crate::stage1::*;

use rand_distr::weighted::WeightedIndex;
use rand_distr::{Distribution, Normal};
use rand_pcg::Pcg32;
use serde::Deserialize;
use std::collections::HashMap;
use std::iter;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, Default)]
/// This structure holds the flow that is being built. Since we cannot instance all the variables
/// at the same time, each variable is an Option
struct IntermediateVector {
    dst_port: Option<u16>,
    ttl_client: Option<u8>,
    ttl_server: Option<u8>,
    fwd_packets_count: Option<usize>,
    bwd_packets_count: Option<usize>,
    timestamp: Option<Duration>,
    proto: Option<Protocol>,
    tcp_flags: Option<TCPEndFlags>,
}

// impl From<PartiallyDefinedFlowData> for Flow {
//     fn from(p: PartiallyDefinedFlowData) -> Self {
//         let d = FlowData {
//             src_ip: p.src_ip.unwrap(),
//             dst_ip: p.dst_ip.unwrap(),
//             src_port: p.src_port.unwrap(),
//             dst_port: p.dst_port.unwrap(),
//             ttl_client: p.ttl_client.unwrap(),
//             ttl_server: p.ttl_server.unwrap(),
//             fwd_packets_count: p.fwd_packets_count,
//             bwd_packets_count: p.bwd_packets_count,
//             timestamp: p.timestamp.unwrap(),
//         };
//         // match p.proto.unwrap() {
//         //     Protocol::TCP => Flow::TCP(d, p.tcp_flags.unwrap()),
//         //     Protocol::UDP => Flow::UDP(d),
//         //     Protocol::ICMP => Flow::ICMP(d),
//         // }
//         p.proto.unwrap().wrap(d)
//     }
// }

// impl PartiallyDefinedFlowData {
//     fn set_value(&mut self, rng: &mut impl RngCore, f: &Feature, index: usize) {
//         todo!()
//         // match f {
//         //     Feature::SrcIP(v) => self.src_ip = Some(v.0[index]),
//         //     Feature::DstIP(v) => self.dst_ip = Some(v.0[index]),
//         //     Feature::DstPt(v) => self.dst_port = Some(v[index]),
//         //     Feature::FwdPkt(v) => self.fwd_packets_count = Some(v.0[index].sample(rng) as usize),
//         //     Feature::BwdPkt(v) => self.bwd_packets_count = Some(v.0[index].sample(rng) as usize),
//         //     Feature::Duration(_) => (),
//         //     Feature::L4Proto(v) => self.proto = Some(v[0]),
//         //     Feature::Flags(_) => (),
//         //     _ => todo!(),
//         // }
//     }
// }

/// A node of the Bayesian network
#[derive(Debug, Clone)]
struct BayesianNetworkNode {
    index: usize, // overall index, unique across the several BNs
    feature: Feature,
    cpt: Option<CPT>,    // TimeBin has no CPT
    parents: Vec<usize>, // indices in the Bayesian network’s nodes
    parents_cardinality: Vec<usize>, // the cardinality of each parents. Used to compute the index
                         // in the cpt
}

#[derive(Debug, Clone)]
#[allow(clippy::upper_case_acronyms)]
/// A list of application layer protocol
enum L7Proto {
    HTTP,
    HTTPS,
    SSH,
    DNS,
    DHCP,
    SMTP,
    Telnet,
    IMAPS,
    MQTT,
    // TODO complete
}

impl L7Proto {
    /// Default destination port that is used if a configuration file does not override it
    fn get_default_port(&self) -> u16 {
        match self {
            L7Proto::HTTP => 80,
            L7Proto::HTTPS => 443,
            L7Proto::SSH => 22,
            L7Proto::DNS => 53,
            L7Proto::DHCP => 67,
            L7Proto::SMTP => 587,
            L7Proto::Telnet => 23,
            L7Proto::IMAPS => 993,
            L7Proto::MQTT => 1883,
            // _ => todo!()
        }
    }
}

#[derive(Debug, Clone)]
/// The TCP end flags
enum TCPEndFlags {
    None,
    R,
    FAndNotR,
    NotFAndNotR,
}

#[derive(Debug, Clone)]
/// The set of random variables that can appear in a Bayesian network
enum Feature {
    // for each feature, we associate a domain
    TimeBin(usize), // cardinality only
    SrcIpRole(Vec<String>),
    DstIpRole(Vec<String>),
    SrcIp(Vec<Ipv4Addr>),     // the IP comes from the config
    DstIp(Vec<Ipv4Addr>),     // the IP comes from the config
    DstPt(Vec<u16>),          // the port comes from the config (must be chosen after the dest IP)
    FwdPkt(Vec<Normal<f64>>), // the exact number is sampled from a Gaussian distribution afterward
    BwdPkt(Vec<Normal<f64>>), // idem
    L7Proto(Vec<L7Proto>),
    L4Proto(Vec<Protocol>),
    EndFlags(Vec<TCPEndFlags>),
}

impl Feature {
    fn get_cardinality(&self) -> usize {
        match &self {
            Feature::SrcIpRole(v) | Feature::DstIpRole(v) => v.len(),
            Feature::SrcIp(v) | Feature::DstIp(v) => v.len(),
            Feature::DstPt(v) => v.len(),
            Feature::FwdPkt(v) | Feature::BwdPkt(v) => v.len(),
            Feature::L4Proto(v) => v.len(),
            Feature::L7Proto(v) => v.len(),
            Feature::EndFlags(v) => v.len(),
            Feature::TimeBin(card) => *card,
        }
    }
}

// impl From<Vec<String>> for Ipv4Vector {
//     fn from(v: Vec<String>) -> Ipv4Vector {
//         // ignore non-IPv4, like anonymised public IP addresses
//         Ipv4Vector(v.into_iter().flat_map(|s| s.parse()).collect())
//     }
// }

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone)]
/// A conditional probability table
struct CPT(Vec<WeightedIndex<f32>>);

impl BayesianNetworkNode {
    /// Sample the value of one variable and update the vector with it
    fn sample_index(&self, rng: &mut impl RngCore, current: &[usize]) -> usize {
        let mut parents_index = 0;
        for (index, card) in self.parents.iter().zip(self.parents_cardinality.iter()) {
            parents_index = parents_index * card + current[*index]
        }
        match &self.cpt {
            None => panic!("Trying to sample a TimeBin"),
            Some(cpt) => cpt.0.get(parents_index).unwrap().sample(rng),
        }
    }
}

#[derive(Debug)]
/// A Bayesian network, which is simply a collection of nodes
struct BayesianNetwork(Vec<BayesianNetworkNode>);

impl BayesianNetwork {
    /// Sample a vector from the Bayesian network
    fn sample(
        &self,
        rng: &mut impl RngCore,
        discrete_vector: &mut Vec<usize>,
        output_vector: &mut IntermediateVector,
    ) {
        for v in self.0.iter() {
            let i = v.sample_index(rng, &discrete_vector);
            discrete_vector.push(i);
            match &v.feature {
                Feature::SrcIpRole(_) => (),
                Feature::DstIpRole(_) => (),
                Feature::L7Proto(v) => output_vector.dst_port = Some(v[i].get_default_port()),
                Feature::SrcIp(v) => todo!(),
                Feature::DstIp(v) => todo!(),
                Feature::DstPt(v) => todo!(),
                Feature::FwdPkt(v) => todo!(),
                Feature::BwdPkt(v) => todo!(),
                Feature::L4Proto(v) => todo!(),
                Feature::EndFlags(v) => todo!(),
                Feature::TimeBin(card) => todo!(),
            }
        }
    }
}

// BIFXML format

#[derive(Deserialize, Debug)]
#[serde(rename_all = "UPPERCASE")]
// The root element
pub struct Bif {
    network: Network,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "UPPERCASE")]
pub struct Network {
    name: String,            // TODO paramétrer dans agrum
    property: String,        // learning software
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

/// The model with all the data
pub struct BayesianModel {
    bn_common: BayesianNetwork,
    bn_tcp: BayesianNetwork,
    bn_udp: BayesianNetwork,
}

/// Stage 1: generates flow descriptions
#[derive(Clone)]
#[allow(unused)]
pub struct BNGenerator {
    model: Arc<BayesianModel>,
    online: bool, // used to generate the TTL, either initial or at the capture point
}

#[derive(Deserialize, Debug, Clone)]
struct AdditionalData {
    s0_bin_count: usize,
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
        let bn_additional_data: AdditionalData = serde_json::from_str(include_str!(
            "../../default_models/bn/bn_additional_data.json"
        ))
        .unwrap();

        let bn_common: Bif =
            serde_xml_rs::from_str(include_str!("../../default_models/bn/bn_common.bifxml"))
                .unwrap();
        let mut processed_bn_common = BayesianNetwork(vec![]);
        let mut overall_index: usize = 0; // common index across the BNs
        let mut name_to_index: HashMap<String, usize> = HashMap::new();
        for (v, def) in bn_common
            .network
            .variable
            .into_iter()
            .zip(bn_common.network.definition)
        {
            // let def = bn_common.network.definition[index];
            assert_eq!(v.name, def.variable); // we assume the order is the same between
            // <variable> and <definition>
            name_to_index.insert(v.name, overall_index);
            let parents: Vec<usize> = def
                .given
                .into_iter()
                .map(|v| {
                    *name_to_index
                        .get(&v)
                        .expect("Variable not in topological order!")
                })
                .collect();
            let proba: Vec<f64> = def
                .table
                .split_ascii_whitespace()
                .into_iter()
                .map(|s| s.parse::<f64>().unwrap())
                .collect();
            for line in proba.chunks(v.outcome.len()) {
                WeightedIndex::new(line);
            }
            let cpt = todo!();
            let feature = match v.name.as_str() {
                "Time" => Feature::TimeBin(bn_additional_data.s0_bin_count),
                "Src IP Role" => Feature::SrcIpRole(v.outcome),
                "Dst IP Role" => Feature::DstIpRole(v.outcome),
                "Applicative Protocol" => Feature::L7Proto(v.outcome),
                _ => unreachable!(),
            };
            let parents_cardinality = vec![];
            for p in parents.iter() {
                parents_cardinality.push(
                    processed_bn_common
                        .0
                        .get(*p)
                        .expect("Variables in BIFXML not in topological order!")
                        .feature
                        .get_cardinality(),
                )
            }
            let node = BayesianNetworkNode {
                index: overall_index, // overall index, unique across the several BNs
                feature,
                parents, // indices in the Bayesian network’s nodes
                parents_cardinality,
                cpt,
            };
            processed_bn_common.0.push(node);
            overall_index += 1;
        }

        let bn_tcp: Bif =
            serde_xml_rs::from_str::<Bif>(include_str!("../../default_models/bn/bn_tcp.bifxml"))
                .unwrap();
        let bn_udp: Bif =
            serde_xml_rs::from_str::<Bif>(include_str!("../../default_models/bn/bn_udp.bifxml"))
                .unwrap();

        log::warn!("Chargement réussi");
    }

    pub fn new(model: Arc<BayesianModel>, online: bool) -> Self {
        // TODO: adapter le modèle à la config !

        BNGenerator { model, online }
    }
}

impl Stage1 for BNGenerator {
    /// Generates flows
    fn generate_flows(&self, ts: SeededData<TimePoint>) -> impl Iterator<Item = SeededData<Flow>> {
        let mut rng = Pcg32::seed_from_u64(ts.seed);
        iter::empty::<SeededData<Flow>>()
        // let mut data: PartiallyDefinedFlowData = self.model.bn.sample(&mut rng);
        // data.timestamp = Some(ts.data.unix_time); // TODO! use date_time
        // data.ttl_client = Some(self.config.get_default_ttl(&data.src_ip.unwrap()));
        // data.ttl_server = Some(self.config.get_default_ttl(&data.dst_ip.unwrap()));
        // iter::once(SeededData {
        //     seed: rng.next_u64(),
        //     data: data.into(),
        // })
    }
}
