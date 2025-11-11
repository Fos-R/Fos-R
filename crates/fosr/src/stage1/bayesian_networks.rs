use crate::stage1::*;

use chrono::Timelike;
use rand_distr::weighted::WeightedIndex;
use rand_distr::{Distribution, Normal};
use rand_pcg::Pcg32;
use serde::Deserialize;
use std::collections::HashMap;
use std::collections::HashSet;
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
    src_ip: Option<Ipv4Addr>,
    dst_ip: Option<Ipv4Addr>,
}

impl From<IntermediateVector> for Flow {
    fn from(p: IntermediateVector) -> Self {
        let d = FlowData {
            src_ip: p.src_ip.unwrap(),
            dst_ip: p.dst_ip.unwrap(),
            src_port: 0,
            dst_port: p.dst_port.unwrap(),
            ttl_client: p.ttl_client.unwrap(),
            ttl_server: p.ttl_server.unwrap(),
            fwd_packets_count: p.fwd_packets_count.unwrap(),
            bwd_packets_count: p.bwd_packets_count.unwrap(),
            timestamp: p.timestamp.unwrap(),
        };
        p.proto.unwrap().wrap(d)
    }
}

/// A node of the Bayesian network
#[derive(Debug, Clone)]
struct BayesianNetworkNode {
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
    CanonBjmp,
    KMS,
    MulticastDNS,
    NTP,
    Unknown, // TODO properly
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
            L7Proto::CanonBjmp => 8612,
            L7Proto::KMS => 1688,
            L7Proto::MulticastDNS => 5353,
            L7Proto::NTP => 123,
            L7Proto::Unknown => 9999,
            // _ => todo!()
        }
    }
}

// TODO: refaire proprement
impl From<String> for L7Proto {
    fn from(s: String) -> L7Proto {
        match s.as_str() {
            "HTTP" => L7Proto::HTTP,
            "HTTPS" => L7Proto::HTTPS,
            "SSH" => L7Proto::SSH,
            "DNS" => L7Proto::DNS,
            "DHCP" => L7Proto::DHCP,
            "SMTP" => L7Proto::SMTP,
            "Telnet" => L7Proto::Telnet,
            "IMAPS" => L7Proto::IMAPS,
            "MQTT" => L7Proto::MQTT,
            "Canon-bjmp" => L7Proto::CanonBjmp,
            "KMS" => L7Proto::KMS,
            "Multicast DNS" => L7Proto::MulticastDNS,
            "NTP" => L7Proto::NTP,
            _ => L7Proto::Unknown,
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

impl TCPEndFlags {
    fn iter() -> [TCPEndFlags; 4] {
        [
            TCPEndFlags::None,
            TCPEndFlags::R,
            TCPEndFlags::FAndNotR,
            TCPEndFlags::NotFAndNotR,
        ]
    }
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
    EndFlags,
}

#[allow(clippy::upper_case_acronyms)]
/// A conditional probability table
type CPT = Vec<WeightedIndex<f64>>;

impl BayesianNetworkNode {
    /// Sample the value of one variable and update the vector with it
    fn sample_index(&self, rng: &mut impl RngCore, current: &[Option<usize>]) -> usize {
        let mut parents_index = 0;
        for (index, card) in self.parents.iter().zip(self.parents_cardinality.iter()) {
            parents_index = parents_index * card + current[*index].unwrap()
        }
        match &self.cpt {
            None => panic!("Trying to sample a TimeBin"),
            Some(cpt) => cpt.get(parents_index).unwrap().sample(rng),
        }
    }
}

#[derive(Debug)]
/// A Bayesian network, which is simply a collection of nodes
struct BayesianNetwork {
    nodes: Vec<BayesianNetworkNode>,
}

impl BayesianNetwork {
    /// Sample a vector from the Bayesian network
    fn sample(
        &self,
        rng: &mut impl RngCore,
        discrete_vector: &mut Vec<Option<usize>>,
    ) -> IntermediateVector {
        let mut domain_vector: IntermediateVector = IntermediateVector::default();
        for v in self.nodes.iter() {
            log::trace!("Sampling {:?}", v.feature);
            // TODO: do not sample TCP variables for UDP connections, etc.
            if !matches!(v.feature, Feature::TimeBin(_)) {
                if true {
                    let i = v.sample_index(rng, discrete_vector);
                    discrete_vector.push(Some(i));
                    match &v.feature {
                        Feature::SrcIpRole(_) => (),
                        Feature::DstIpRole(_) => (),
                        Feature::L7Proto(v) => domain_vector.dst_port = Some(v[i].get_default_port()),
                        Feature::SrcIp(v) => domain_vector.src_ip = Some(v[i]),
                        Feature::DstIp(v) => domain_vector.dst_ip = Some(v[i]),
                        Feature::DstPt(v) => domain_vector.dst_port = Some(v[i]),
                        Feature::FwdPkt(v) => {
                            domain_vector.fwd_packets_count = Some(v[i].sample(rng) as usize)
                        }
                        Feature::BwdPkt(v) => {
                            domain_vector.bwd_packets_count = Some(v[i].sample(rng) as usize)
                        }
                        Feature::L4Proto(v) => domain_vector.proto = Some(v[i]),
                        Feature::EndFlags => {
                            domain_vector.tcp_flags = Some(TCPEndFlags::iter()[i].clone())
                        }
                        Feature::TimeBin(card) => unreachable!(),
                    }
                } else {
                    discrete_vector.push(None);
                }
            } // if it’s "Time", do not push any value (it was already done previously)
        }
        domain_vector
    }
}

/// The model with all the data
pub struct BayesianModel {
    bn: BayesianNetwork,
    // bn_tcp: BayesianNetwork,
    // bn_udp: BayesianNetwork,
    bn_additional_data: AdditionalData,
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
    TCP_out_pkt_gaussians: GaussianDistribs,
    TCP_in_pkt_gaussians: GaussianDistribs,
    UDP_out_pkt_gaussians: GaussianDistribs,
    UDP_in_pkt_gaussians: GaussianDistribs,
}

impl GaussianDistribs {
    fn to_normals(&self) -> Vec<Normal<f64>> {
        self.mu
            .iter()
            .zip(self.cov.iter())
            .map(|(mu, cov)| Normal::new(*mu, cov.sqrt()).unwrap())
            .collect()
    }
}

#[derive(Deserialize, Debug, Clone)]
struct GaussianDistribs {
    mu: Vec<f64>,
    cov: Vec<f64>,
}

// Used only for computing the topological order
struct TopologicalNode {
    parents: HashSet<String>,
    children: Vec<String>,
}

impl BayesianModel {
    pub fn load() -> BayesianModel {
        let bn_additional_data: AdditionalData = serde_json::from_str(include_str!(
            "../../default_models/bn/bn_additional_data.json"
        ))
        .unwrap();

        // The BIFXML Bayesian network is converted to a "BayesianNetwork"
        // let mut overall_index: usize = 0; // common index across the BNs
        // let mut name_to_index: HashMap<String, usize> = HashMap::new();

        log::info!("Loading high-level BN");
        let mut bif_common = bifxml::from_str(include_str!("../../default_models/bn/bn_common.bifxml"));
        log::info!("Loading TCP BN");
        let mut bif_tcp = bifxml::from_str(include_str!("../../default_models/bn/bn_tcp.bifxml"));
        bif_common.merge(bif_tcp, Protocol::TCP);
        log::info!("Loading UDP BN");
        let mut bif_udp = bifxml::from_str(include_str!("../../default_models/bn/bn_udp.bifxml"));
        bif_common.merge(bif_udp, Protocol::UDP);

        // TODO: vérifier la cohérence des cardinalités avec un assert (entre bn_common et chacun
        // des deux autres)

        let bn_common = bn_from_bif(bif_common, &bn_additional_data, None);

        BayesianModel {
            bn: bn_common,
            bn_additional_data,
        }
    }
}

fn bn_from_bif(
    mut network: bifxml::Network,
    bn_additional_data: &AdditionalData,
    proto: Option<Protocol>,
) -> BayesianNetwork {
    let mut processed_bn = BayesianNetwork { nodes: vec![] };

    // first, start computing the topological order
    let mut nodes: HashMap<String, TopologicalNode> = HashMap::new();
    let mut roots = vec![];

    for def in network.definition.iter() {
        nodes.insert(
            def.variable.clone(),
            TopologicalNode {
                parents: HashSet::new(),
                children: vec![],
            },
        );
        if def.given.is_none() {
            roots.push(def.variable.clone());
        }
    }

    if let Some(p) = roots.iter().position(|s| s.as_str() == "Time") {
        roots.swap(p, 0); // Time must be the first variable if present
    }

    for def in network.definition.iter() {
        if let Some(given) = &def.given {
            for v in given.iter() {
                nodes
                    .get_mut(&def.variable)
                    .unwrap()
                    .parents
                    .insert(v.clone());
                nodes
                    .get_mut(v)
                    .unwrap()
                    .children
                    .push(def.variable.clone());
            }
        }
    }

    let mut topo_order: Vec<String> = vec![];

    // Kahn’s algorithm
    while let Some(v) = roots.pop() {
        let children = nodes.get(&v).unwrap().children.clone();
        for c in children {
            let parents = &mut nodes.get_mut(&c.clone()).unwrap().parents;
            if parents.remove(&v) && parents.is_empty() {
                roots.push(c.clone());
            }
        }
        topo_order.push(v);
    }

    // let mut sorted_network: bifxml::Network = bifxml::Network {
    //     name: network.name,
    //     property: network.property,
    //     variable: vec![],
    //     definition: vec![],
    // };

    let mut variable = vec![];
    let mut definition = vec![];
    for v in topo_order {
        for (index, var) in network.variable.iter().enumerate() {
            if var.name == v {
                variable.push(var.clone());
                definition
                    .push(network.definition[index].clone());
            }
        }
    }

    // network = sorted_network;

    let mut var_names: Vec<String> = vec![];

    for (v, def) in variable.iter().zip(definition) {
        assert_eq!(v.name, def.variable); // we assume the order is the same between
        // <variable> and <definition>
        // let ignored_during_generation = var_names.contains(&v.name);
        // dbg!(&v.name);
        // dbg!(ignored_during_generation);

        // if !ignored_during_generation {
        // name_to_index.insert(v.name.clone(), overall_index);

        // global index of parents
        let parents: Vec<usize> = def
            .given
            .clone()
            .unwrap_or(vec![])
            .into_iter()
            .map(|v| var_names.iter_mut().position(|s| s.as_str() == v).unwrap())
            .collect();

        let cpt: CPT = def
            .table
            .split_ascii_whitespace()
            .map(|s| s.parse::<f64>().unwrap())
            .collect::<Vec<_>>()
            .chunks(v.outcome.len())
            .map(|l| WeightedIndex::new(l).unwrap())
            .collect();

        println!("{}", def.variable);
        let feature: Option<Feature> = match v.name.as_str() {
            "Time" => Some(Feature::TimeBin(bn_additional_data.s0_bin_count)),
            "Src IP Role" => Some(Feature::SrcIpRole(v.outcome.clone())),
            "Src IP" => Some(Feature::SrcIp(v.outcome.clone().into_iter().map(|v| v.parse().unwrap()).collect())),
            "Dst IP Role" => Some(Feature::DstIpRole(v.outcome.clone())),
            "Dst IP" => Some(Feature::DstIp(v.outcome.clone().into_iter().map(|v| v.parse().unwrap()).collect())),
            "Applicative Proto" => Some(Feature::L7Proto(
                v.outcome.clone().into_iter().map(|s| s.into()).collect(),
            )),
            "Proto" => Some(Feature::L4Proto(
                v.outcome.clone().into_iter().map(|s| s.into()).collect(),
            )),

            "Cat Out Packet TCP" => Some(Feature::FwdPkt(
                bn_additional_data.TCP_out_pkt_gaussians.to_normals(),
            )),
            "Cat In Packet TCP" => Some(Feature::FwdPkt(
                bn_additional_data.TCP_in_pkt_gaussians.to_normals(),
            )),
            "End Flags TCP" => Some(Feature::EndFlags),

            "Cat Out Packet UDP" => Some(Feature::FwdPkt(
                bn_additional_data.UDP_out_pkt_gaussians.to_normals(),
            )),
            "Cat In Packet UDP" => Some(Feature::FwdPkt(
                bn_additional_data.UDP_in_pkt_gaussians.to_normals(),
            )),
            _ => None,
        };

        // log::info!("Cardinality of {}: {}", def.variable, feature.get_cardinality());

        if let Some(feature) = feature {
            // this feature is duplicated (for example "Time UDP"), so we do not include it
            var_names.push(v.name.clone());
            let mut variables = variable.clone();
            let parents_cardinality = def
                .given
                .unwrap_or(vec![])
                .into_iter()
                .map(|v| {
                    variables
                        .iter_mut()
                        .find(|s| s.name.as_str() == v)
                        .unwrap()
                        .outcome
                        .len()
                })
                .collect();

            println!("{parents_cardinality:?}");

            let cpt = if matches!(feature, Feature::TimeBin(_)) {
                None
            } else {
                Some(cpt)
            };
            let node = BayesianNetworkNode {
                // index: var_names.len() - 1, // it was the last pushed name
                feature,
                parents, // indices in the Bayesian network’s nodes
                parents_cardinality,
                cpt,
                // ignored_during_generation,
            };
            processed_bn.nodes.push(node);
        }
        // }
    }

    processed_bn
}

impl BNGenerator {
    pub fn new(model: Arc<BayesianModel>, online: bool) -> Self {
        // TODO: adapter le modèle à la config !
        BNGenerator { model, online }
    }
}

impl Stage1 for BNGenerator {
    /// Generates flows
    fn generate_flows(&self, ts: SeededData<TimePoint>) -> impl Iterator<Item = SeededData<Flow>> {
        let mut rng = Pcg32::seed_from_u64(ts.seed);
        let mut discrete_vector: Vec<Option<usize>> = vec![];
        discrete_vector.push(Some(
            (ts.data.date_time.num_seconds_from_midnight() as usize)
                / self.model.bn_additional_data.s0_bin_count,
        ));
        let mut domain_vector = self.model.bn.sample(&mut rng, &mut discrete_vector);
        domain_vector.timestamp = Some(ts.data.unix_time);
        iter::once(SeededData {
            seed: rng.next_u64(),
            data: domain_vector.into(),
        })

        // iter::empty::<SeededData<Flow>>()
        // data.timestamp = Some(ts.data.unix_time); // TODO! use date_time
        // data.ttl_client = Some(self.config.get_default_ttl(&data.src_ip.unwrap()));
        // data.ttl_server = Some(self.config.get_default_ttl(&data.dst_ip.unwrap()));
        // iter::once(SeededData {
        //     seed: rng.next_u64(),
        //     data: data.into(),
        // })
    }
}
