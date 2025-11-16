use crate::config;
use crate::stage1::*;

use chrono::Timelike;
use rand_distr::weighted::WeightedIndex;
use rand_distr::{Distribution, Normal};
use rand_pcg::Pcg32;
use serde::Deserialize;

use std::cmp::min;
use std::collections::HashMap;
use std::collections::HashSet;
use std::iter;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, Default)]
/// This structure holds the flow that is being built. Since we cannot instance all the variables
/// at the same time, each variable is an Option
struct IntermediateVector {
    src_ip_role: Option<IpRole>,
    dst_ip_role: Option<IpRole>,
    l7_proto: Option<L7Proto>,
    dst_port: Option<u16>,
    ttl_client: Option<u8>,
    ttl_server: Option<u8>,
    fwd_packets_count: Option<usize>,
    bwd_packets_count: Option<usize>,
    timestamp: Option<Duration>,
    proto: Option<Protocol>,
    tcp_flags: Option<TCPEndFlags>,
    src_ip: Option<Ipv4Addr>, // if None, randomly sampled
    dst_ip: Option<Ipv4Addr>, // if None, randomly sampled
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
    proto_specific: Option<Protocol>,
    feature: Feature,
    cpt: Option<CPT>,    // TimeBin has no CPT
    parents: Vec<usize>, // indices in the Bayesian network’s nodes
    parents_cardinality: Vec<usize>, // the cardinality of each parents. Used to compute the index
                         // in the cpt
}

#[derive(Debug, Clone)]
enum IpRole {
    Client,
    Server,
    Internet,
}

// TODO: refaire proprement
impl From<String> for IpRole {
    fn from(s: String) -> IpRole {
        match s.as_str() {
            "Client" => IpRole::Client,
            "Server" => IpRole::Server,
            "Internet" => IpRole::Internet,
            _ => unreachable!(),
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
enum AnonymizedIpv4Addr {
    Public,
    Local(Ipv4Addr),
}

#[derive(Debug, Clone)]
/// The set of random variables that can appear in a Bayesian network
enum Feature {
    // for each feature, we associate a domain
    TimeBin(usize), // cardinality only
    SrcIpRole(Vec<IpRole>),
    DstIpRole(Vec<IpRole>),
    SrcIp(Vec<AnonymizedIpv4Addr>), // the IP comes from the config
    DstIp(Vec<AnonymizedIpv4Addr>), // the IP comes from the config
    DstPt(Vec<u16>), // the port comes from the config (must be chosen after the dest IP)
    FwdPkt(Vec<Normal<f64>>), // the exact number is sampled from a Gaussian distribution afterward
    BwdPkt(Vec<Normal<f64>>), // idem
    L7Proto(Vec<L7Proto>),
    L4Proto(Vec<Protocol>),
    EndFlags,
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
            Feature::EndFlags => TCPEndFlags::iter().len(),
            Feature::TimeBin(card) => *card,
        }
    }
}

#[allow(clippy::upper_case_acronyms)]
/// A conditional probability table
type CPT = Vec<WeightedIndex<f64>>;

impl BayesianNetworkNode {
    /// Sample the value of one variable and update the vector with it
    fn sample_index(&self, rng: &mut impl RngCore, current: &[Option<usize>]) -> usize {
        let mut parents_index = 0;
        // println!("Sample index of {:?}", self.feature);
        for (index, card) in self.parents.iter().zip(self.parents_cardinality.iter()) {
            // println!(
            //     "Parent {}. Value: {:?}. Cpt len: {}.",
            //     index, current[*index], self.cpt.as_ref().unwrap().len()
            // );
            parents_index = parents_index * card + current[*index].unwrap()
        }
        match &self.cpt {
            None => panic!("Trying to sample a TimeBin"),
            Some(cpt) => {
                let index = cpt.get(parents_index).unwrap().sample(rng);
                // verify that the index in inside the possible values
                assert!(index < self.feature.get_cardinality());
                index
            }
        }
    }
}

#[derive(Debug)]
/// A Bayesian network, which is simply a collection of nodes
struct BayesianNetwork {
    nodes: Vec<BayesianNetworkNode>,
}

fn sample_random_ip(rng: &mut impl RngCore) -> Ipv4Addr {
    Ipv4Addr::from_bits(rng.next_u32())
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
            // log::info!("Sampling {:?} (index: {index})", v.feature);
            if !matches!(v.feature, Feature::TimeBin(_)) {
                // do not sample TCP variables for UDP connections, etc.
                if v.proto_specific
                    .is_none_or(|p| p == domain_vector.proto.unwrap())
                {
                    let i = v.sample_index(rng, discrete_vector);
                    // println!("Sampled value for {:?}: {}", v.feature, i);
                    discrete_vector.push(Some(i));
                    match &v.feature {
                        Feature::SrcIpRole(v) => domain_vector.src_ip_role = Some(v[i].clone()),
                        Feature::DstIpRole(v) => domain_vector.dst_ip_role = Some(v[i].clone()),
                        Feature::L7Proto(v) => domain_vector.l7_proto = Some(v[i].clone()),
                        Feature::SrcIp(v) => match v[i] {
                            AnonymizedIpv4Addr::Local(p) => domain_vector.src_ip = Some(p),
                            AnonymizedIpv4Addr::Public => {
                                domain_vector.src_ip = Some(sample_random_ip(rng))
                            }
                        },
                        Feature::DstIp(v) => match v[i] {
                            AnonymizedIpv4Addr::Local(p) => domain_vector.dst_ip = Some(p),
                            AnonymizedIpv4Addr::Public => {
                                domain_vector.dst_ip = Some(sample_random_ip(rng))
                            }
                        },
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
                        Feature::TimeBin(_) => unreachable!(),
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
    ttl: HashMap<Ipv4Addr, u8>,
    tcp_out_pkt_gaussians: GaussianDistribs,
    tcp_in_pkt_gaussians: GaussianDistribs,
    udp_out_pkt_gaussians: GaussianDistribs,
    udp_in_pkt_gaussians: GaussianDistribs,
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

impl BayesianModel {
    pub fn load() -> Self {
        let bn_additional_data: AdditionalData = serde_json::from_str(include_str!(
            "../../default_models/bn/bn_additional_data.json"
        ))
        .unwrap();

        // log::info!("Loading high-level BN");
        let mut bif_common =
            bifxml::from_str(include_str!("../../default_models/bn/bn_common.bifxml"));
        // log::info!("Loading TCP BN");
        let bif_tcp = bifxml::from_str(include_str!("../../default_models/bn/bn_tcp.bifxml"));
        bif_common.merge(bif_tcp, Protocol::TCP);
        // log::info!("Loading UDP BN");
        let bif_udp = bifxml::from_str(include_str!("../../default_models/bn/bn_udp.bifxml"));
        bif_common.merge(bif_udp, Protocol::UDP);

        let bn_common = bn_from_bif(bif_common, &bn_additional_data);

        BayesianModel {
            bn: bn_common,
            bn_additional_data,
        }
    }

    // il faut mettre à jour : SrcIp, DstIp, L7Proto

    pub fn apply_config(&mut self, config: &config::Configuration) {
        for node in self.bn.nodes.iter_mut() {
            match &mut node.feature {
                // we set the probability of absent services to 0
                Feature::L7Proto(v) => {
                    // TODO: mettre un warning si un service de la config n’est pas présent dans le
                    // dataset
                    // get services present in the configuration
                    let services = config.get_services();
                    for s in services.iter() {
                        if !v.contains(s) {
                            log::warn!("Service {s:?} is not present in the original dataset and will not be generated");
                        }
                    }
                    // create a list of all the indices to set the probability to 0
                    let weight_update: Vec<(usize, &f64)> = v.iter().enumerate().filter_map(|(index,proto)| if services.contains(proto) { None } else { Some((index, &0.0f64)) }).collect();
                    // modify all the probability distributions
                    node.cpt.as_mut().unwrap().iter_mut().for_each(|w: &mut WeightedIndex<f64>| w.update_weights(&weight_update).unwrap());
                },
                Feature::SrcIp(v) => {


                }
                // Feature::
                // Feature::SrcIp(v) => (),
                _ => (),
            }
        }
    }
}

fn bn_from_bif(network: bifxml::Network, bn_additional_data: &AdditionalData) -> BayesianNetwork {
    // Used only for computing the topological order
    struct TopologicalNode {
        parents: HashSet<String>,
        children: Vec<String>,
    }

    let mut processed_bn = BayesianNetwork { nodes: vec![] };

    // first, start computing the topological order
    let mut nodes: HashMap<String, TopologicalNode> = HashMap::new();
    let mut roots = vec![];

    // convert def to TopologicalNode
    for def in network.definition.iter() {
        nodes.insert(
            def.variable.clone(),
            TopologicalNode {
                parents: HashSet::new(),
                children: vec![],
            },
        );
        // identify nodes without parents
        if def.given.is_none() {
            roots.push(def.variable.clone());
        }
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

    // If time is present, it should be the first one
    if let Some(p) = topo_order.iter().position(|s| s.as_str() == "Time") {
        topo_order.swap(p, 0); // Time must be the first variable if present
    }

    // println!("Topological order: {topo_order:?}");

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
                definition.push(network.definition[index].clone());
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

        // println!("{}", def.variable);
        let feature: Option<Feature> = match v.name.as_str() {
            "Time" => Some(Feature::TimeBin(bn_additional_data.s0_bin_count)),
            "Src IP Role" => Some(Feature::SrcIpRole(
                v.outcome.clone().into_iter().map(|s| s.into()).collect(),
            )),
            "Src IP Addr" => Some(Feature::SrcIp(
                v.outcome
                    .clone()
                    .into_iter()
                    .map(|v| match v.parse().ok() {
                        Some(ip) => AnonymizedIpv4Addr::Local(ip),
                        None => AnonymizedIpv4Addr::Public,
                    })
                    .collect(),
            )),
            "Dst IP Role" => Some(Feature::DstIpRole(
                v.outcome.clone().into_iter().map(|s| s.into()).collect(),
            )),
            "Dst IP Addr" => Some(Feature::DstIp(
                v.outcome
                    .clone()
                    .into_iter()
                    .map(|v| match v.parse().ok() {
                        Some(ip) => AnonymizedIpv4Addr::Local(ip),
                        None => AnonymizedIpv4Addr::Public,
                    })
                    .collect(),
            )),
            "Applicative Proto" => Some(Feature::L7Proto(
                v.outcome.clone().into_iter().map(|s| s.into()).collect(),
            )),
            "Proto" => Some(Feature::L4Proto(
                v.outcome.clone().into_iter().map(|s| s.into()).collect(),
            )),
            "Dst Pt" => Some(Feature::DstPt(
                v.outcome
                    .clone()
                    .into_iter()
                    .map(|s| u16::from_str(&s.strip_prefix("port-").unwrap()).unwrap())
                    .collect(),
            )),

            "Cat Out Packet TCP" => Some(Feature::FwdPkt(
                bn_additional_data.tcp_out_pkt_gaussians.to_normals(),
            )),
            "Cat In Packet TCP" => Some(Feature::BwdPkt(
                bn_additional_data.tcp_in_pkt_gaussians.to_normals(),
            )),
            "End Flags TCP" => Some(Feature::EndFlags),

            "Cat Out Packet UDP" => Some(Feature::FwdPkt(
                bn_additional_data.udp_out_pkt_gaussians.to_normals(),
            )),
            "Cat In Packet UDP" => Some(Feature::BwdPkt(
                bn_additional_data.udp_in_pkt_gaussians.to_normals(),
            )),
            _ => None,
        };

        // log::info!("Cardinality of {}: {}", def.variable, feature.get_cardinality());

        if let Some(feature) = feature {
            // this feature is duplicated (for example "Time UDP"), so we do not include it
            var_names.push(v.name.clone());
            let mut variables = variable.clone();
            let parents_cardinality: Vec<usize> = def
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

            // ensure that the product of the cardinality of the parents is the number of
            // distribution
            assert_eq!(parents_cardinality.iter().product::<usize>(), cpt.len());

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
                proto_specific: v.proto_specific,
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
        discrete_vector.push(Some(min(
            self.model.bn_additional_data.s0_bin_count - 1,
            (ts.data.date_time.num_seconds_from_midnight() as usize) / 86400
                * self.model.bn_additional_data.s0_bin_count,
        )));
        let mut domain_vector = self.model.bn.sample(&mut rng, &mut discrete_vector);
        domain_vector.timestamp = Some(ts.data.unix_time);
        domain_vector.ttl_client = Some(
            *self
                .model
                .bn_additional_data
                .ttl
                .get(&domain_vector.src_ip.unwrap())
                .unwrap_or(&60),
        );
        domain_vector.ttl_server = Some(
            *self
                .model
                .bn_additional_data
                .ttl
                .get(&domain_vector.dst_ip.unwrap())
                .unwrap_or(&60),
        );
        iter::once(SeededData {
            seed: rng.next_u64(),
            data: domain_vector.into(),
        })
    }
}
