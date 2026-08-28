use crate::models;
use crate::network;
use crate::stage2::*;

use chrono::Timelike;
use pnet::util::MacAddr;
use rand_distr::Distribution;
use rand_distr::Uniform;
use rand_distr::weighted::WeightedIndex;
use rand_pcg::Pcg32;
use std::cmp::min;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt::{Display, Error, Formatter};
use std::iter;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use strum::EnumString;
use rand::prelude::SliceRandom;

#[derive(Debug, Clone, Default)]
/// This structure holds the flow that is being built. Since we cannot instance all the variables
/// at the same time, each variable is an Option
struct IntermediateVector {
    src_ip_role: Option<IpRole>,
    dst_ip_role: Option<IpRole>,
    l7_proto: Option<L7Proto>,
    dst_port: Option<u16>,
    src_port: Option<u16>,
    src_ttl: Option<u8>,
    dst_ttl: Option<u8>,
    packets_count_cluster: Option<usize>,
    // fwd_packets_count: Option<usize>,
    // bwd_packets_count: Option<usize>,
    timestamp: Option<Duration>,
    proto: Option<L4Proto>,
    tcp_flags: Option<TCPConnState>,
    src_ip: Option<Ipv4Addr>, // if None, randomly sampled
    dst_ip: Option<Ipv4Addr>, // if None, randomly sampled
    src_mac: Option<MacAddr>,
    dst_mac: Option<MacAddr>,
}

impl From<IntermediateVector> for Flow {
    fn from(p: IntermediateVector) -> Self {
        let d = FlowData {
            src_ip: p.src_ip.unwrap(),
            dst_ip: p.dst_ip.unwrap(),
            src_port: p.src_port.unwrap(),
            dst_port: p.dst_port.unwrap(),
            src_ttl: p.src_ttl.unwrap(),
            dst_ttl: p.dst_ttl.unwrap(),
            packets_count_cluster: p.packets_count_cluster.unwrap(),
            fwd_packets_count: 0, //p.fwd_packets_count.unwrap(), FIXME
            bwd_packets_count: 0, //p.bwd_packets_count.unwrap(), FIXME
            src_mac: p.src_mac.unwrap(),
            dst_mac: p.dst_mac.unwrap(),
            timestamp: p.timestamp.unwrap(),
            l7_proto: p.l7_proto.unwrap(),
        };
        p.proto.unwrap().wrap(d, p.tcp_flags)
    }
}

/// A node of the Bayesian network
#[derive(Debug, Clone)]
struct BayesianNetworkNode {
    feature: Feature,
    removed_values: HashSet<usize>,
    cpt: Option<CPT>,    // TimeBin has no CPT
    parents: Vec<usize>, // indices in the Bayesian network’s nodes
    parents_cardinality: Vec<usize>, // the cardinality of each parents. Used to compute the index
                         // in the cpt
}

/// Extra information for the transfer learning
#[derive(Debug, Clone)]
struct TransferLearningExtraData {
    local_src_ip_users: HashMap<L7Proto, (Vec<Ipv4Addr>, WeightedIndex<f64>)>,
    local_src_ip_servers: HashMap<L7Proto, (Vec<Ipv4Addr>, WeightedIndex<f64>)>,
    local_dst_ip: HashMap<L7Proto, (Vec<Ipv4Addr>, WeightedIndex<f64>)>,
    local_ttl: HashMap<Ipv4Addr, u8>,
    services_per_server: HashMap<(Ipv4Addr, L7Proto), Vec<L7ProtoWithPort>>,
}

#[derive(Debug, Clone, Copy, EnumString)]
#[strum(
    parse_err_fn = String::from,
    parse_err_ty = String
)]
enum IpRole {
    User,
    Server,
    Internet,
}

#[derive(Debug, Clone)]
enum AnonymizedIpv4Addr {
    Public,
    Local(Ipv4Addr),
}

#[derive(Debug, Clone)]
enum DstPt {
    Random,
    Fixed(u16),
}

#[derive(Debug, Clone)]
/// The set of random variables that can appear in a Bayesian network
enum Feature {
    // for each feature, we associate a domain
    TimeBin(usize), // cardinality only
    SrcIpRole(Vec<IpRole>),
    DstIpRole(Vec<IpRole>),
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
    fn get_value_string(&self, index: usize) -> String {
        match &self {
            // Feature::SrcIpRole(v) | Feature::DstIpRole(v) => format!("{:?}", v[index]),
            Feature::SrcIp(v) | Feature::DstIp(v) => format!("{:?}", v[index]),
            Feature::DstPt(v) => format!("{:?}", v[index]),
            Feature::PktCount(_) => format!("Cluster {index}"),
            Feature::SrcTTL(v) | Feature::DstTTL(v) => format!("{:?}", v[index]),
            Feature::SrcMac(v) | Feature::DstMac(v) => format!("{:?}", v[index]),
            Feature::L4Proto(v) => format!("{:?}", v[index]),
            Feature::L7Proto(v) => format!("{:?}", v[index]),
            Feature::EndFlags(v) => format!("{:?}", v[index]),
            Feature::TimeBin(_) => format!("Time bin {index}"),
            Feature::SrcIpRole(v) | Feature::DstIpRole(v) => format!("{:?}", v[index]),
        }
    }

    fn get_cardinality(&self) -> usize {
        match &self {
            // Feature::SrcIpRole(v) | Feature::DstIpRole(v) => v.len(),
            Feature::SrcIp(v) | Feature::DstIp(v) => v.len(),
            Feature::DstPt(v) => v.len(),
            Feature::PktCount(card) | Feature::TimeBin(card) => *card,
            Feature::SrcTTL(v) | Feature::DstTTL(v) => v.len(),
            Feature::SrcMac(v) | Feature::DstMac(v) => v.len(),
            Feature::SrcIpRole(v) | Feature::DstIpRole(v) => v.len(),
            Feature::L4Proto(v) => v.len(),
            Feature::L7Proto(v) => v.len(),
            Feature::EndFlags(v) => v.len(),
        }
    }
}

#[allow(clippy::upper_case_acronyms)]
/// A conditional probability table
type CPT = Vec<Option<WeightedIndex<f64>>>; // some combination may be impossible

impl BayesianNetworkNode {
    /// Sample the value of one variable and update the vector with it
    fn sample_index(&self, rng: &mut impl Rng, current: &[usize]) -> Result<Option<usize>, String> {
        let mut parents_index = 0;
        // println!("Sample index of {:?}", self.feature);
        // println!("Sample index");
        for (index, card) in self.parents.iter().zip(self.parents_cardinality.iter()) {
            // println!(
            //     "Parent {}. Value: {:?}. Cpt len: {}.",
            //     index,
            //     current[*index],
            //     self.cpt.as_ref().unwrap().len()
            // );
            parents_index = parents_index * card + current[*index];
        }
        // println!("CPT: {:?}", self.cpt);
        match &self.cpt {
            None => Err("No CPT!".to_string()),
            Some(cpt) => Ok(cpt[parents_index].as_ref().map(|w| w.sample(rng))),
        }
    }
}

#[derive(Debug)]
/// A Bayesian network, which is simply a collection of nodes in topological order
struct BayesianNetwork {
    nodes: Vec<BayesianNetworkNode>,
}

fn is_global(addr: &Ipv4Addr) -> bool {
    addr.octets()[0] != 0
        && !addr.is_multicast()
        && !addr.is_broadcast()
        && !addr.is_documentation()
        && !addr.is_link_local()
        && !addr.is_loopback()
        && !addr.is_private()
}

fn sample_random_global_ip(rng: &mut impl Rng) -> Ipv4Addr {
    let mut addr = Ipv4Addr::from_bits(rng.next_u32());
    // rejection sampling
    while !is_global(&addr) {
        // while !addr.is_global() { // TODO: use when not experimental anymore
        addr = Ipv4Addr::from_bits(rng.next_u32());
    }
    addr
}

impl Display for BayesianNetwork {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        for (index, n) in self.nodes.iter().enumerate() {
            if n.parents.is_empty() {
                writeln!(f, "Node {index}: {:?}", n.feature)?;
            } else {
                writeln!(f, "Node {index}: {:?}, parents:", n.feature)?;
            }
            for p in n.parents.iter() {
                writeln!(f, "   Node {p}: {:?}", self.nodes[*p].feature)?;
            }
        }
        Ok(())
    }
}

impl BayesianNetwork {
    /// Sample a vector from the Bayesian network
    fn sample(
        &self,
        rng: &mut impl Rng,
        discrete_vector: &mut Vec<usize>,
    ) -> Result<IntermediateVector, String> {
        // println!("{self:?}");
        let mut try_again = true;
        let mut rejected: u64 = 0;
        let mut domain_vector: IntermediateVector = IntermediateVector::default();
        let mut new_discrete_vector = discrete_vector.clone();
        while try_again {
            try_again = false;
            new_discrete_vector.clone_from(discrete_vector);
            domain_vector = IntermediateVector::default();
            for v in self.nodes.iter() {
                // log::info!("Sampling {:?} (index: {index})", v.feature);
                // println!("Discrete vector: {:?}", new_discrete_vector);
                if !matches!(v.feature, Feature::TimeBin(_)) {
                    let index = v.sample_index(rng, &new_discrete_vector)?;
                    if let Some(i) = index {
                        assert!(i < v.feature.get_cardinality());
                        // println!("Sampled value for {:?}: {}", v.feature, i);
                        new_discrete_vector.push(i);
                        match &v.feature {
                            Feature::SrcIpRole(v) => domain_vector.src_ip_role = Some(v[i]),
                            Feature::DstIpRole(v) => domain_vector.dst_ip_role = Some(v[i]),
                            Feature::SrcTTL(v) => domain_vector.src_ttl = Some(v[i]),
                            Feature::DstTTL(v) => domain_vector.dst_ttl = Some(v[i]),
                            Feature::SrcMac(v) => domain_vector.src_mac = Some(v[i]),
                            Feature::DstMac(v) => domain_vector.dst_mac = Some(v[i]),
                            Feature::L7Proto(v) => domain_vector.l7_proto = Some(v[i]),
                            Feature::SrcIp(v) => match v[i] {
                                AnonymizedIpv4Addr::Local(p) => domain_vector.src_ip = Some(p),
                                AnonymizedIpv4Addr::Public => {
                                    domain_vector.src_ip = Some(sample_random_global_ip(rng));
                                }
                            },
                            Feature::DstIp(v) => match v[i] {
                                AnonymizedIpv4Addr::Local(p) => domain_vector.dst_ip = Some(p),
                                AnonymizedIpv4Addr::Public => {
                                    domain_vector.dst_ip = Some(sample_random_global_ip(rng));
                                }
                            },
                            Feature::DstPt(v) => match v[i] {
                                DstPt::Random => domain_vector.dst_port = None,
                                DstPt::Fixed(p) => domain_vector.dst_port = Some(p),
                            },
                            Feature::PktCount(_) => domain_vector.packets_count_cluster = Some(i),
                            Feature::L4Proto(v) => domain_vector.proto = Some(v[i]),
                            Feature::EndFlags(v) => domain_vector.tcp_flags = Some(v[i]),
                            Feature::TimeBin(_) => unreachable!(),
                        }
                    } else {
                        // log::error!("Rejected");
                        rejected += 1;
                        if rejected > 10000 {
                            return Err("Too many rejections during sampling. Maybe the network file is not compatible with the model learned.".to_string());
                        }
                        if rejected > 10 && (rejected as f64).log10().fract() == 0.0 {
                            log::warn!("Rejected sample ({rejected} times)");
                        }
                        try_again = true;
                        break;
                    }
                }
            } // if it’s "Time", do not push any value (it was already done previously)
        }
        // if rejected >= 10 {
        //     log::info!("Accepted sample ({rejected} times)");
        // }
        *discrete_vector = new_discrete_vector;
        Ok(domain_vector)
    }
}

/// The model with all the data
pub struct BayesianModel {
    bn: BayesianNetwork,
    bin_count: usize,
    transfer_learning: Option<TransferLearningExtraData>,
}

/// Stage 1: generates flow descriptions
#[derive(Clone)]
#[allow(unused)]
pub struct BNGenerator {
    model: Arc<BayesianModel>,
    online: bool, // used to generate the TTL, either initial or at the capture point
}

// remove a value from variable by setting its probability to zero
fn remove_value(node: &mut BayesianNetworkNode, index: usize) -> Result<(), String> {
    node.removed_values.insert(index);
    if node.removed_values.len() == node.feature.get_cardinality() {
        Err(format!(
            "No value of {:?} can lead to a flow compatible with the network",
            node.feature
        ))
    } else if let Some(cpt) = node.cpt.as_mut() {
        for cpt in cpt.iter_mut() {
            if let Some(weights) = cpt {
                let result = weights.update_weights(&[(index, &0.0f64)]);
                if result.is_err() {
                    *cpt = None;
                }
            }
        }
        Ok(())
    } else {
        // We cannot remove values of Time since we do not sample it and it has no CPT
        Ok(())
    }
}

impl BayesianModel {
    pub fn from_source_with_network(
        m: &models::ModelsSource,
        network: &network::Network,
    ) -> Result<Self, String> {

        // We use a seeded RNG so everything is deterministic
        let mut rng = Pcg32::seed_from_u64(12345);

        let bn_string: String = m
            .get_tl_bn()
            .map_err(|e| format!("Cannot find the Bayesian networks: {e}"))?;

        log::trace!("Loading Bayesian network");
        let bif_common = bifxml::from_str(&bn_string)?;

        log::trace!("Converting from BIF");
        let (bn, bin_count) = bn_from_bif(bif_common)?;

        log::info!("Bayesian network has been loaded");

        let mut local_src_ip_users: HashMap<L7Proto, (Vec<Ipv4Addr>, WeightedIndex<f64>)> = HashMap::new();
        let mut local_src_ip_servers: HashMap<L7Proto, (Vec<Ipv4Addr>, WeightedIndex<f64>)> = HashMap::new();
        let mut local_dst_ip: HashMap<L7Proto, (Vec<Ipv4Addr>, WeightedIndex<f64>)> = HashMap::new();

        for s in network.services.iter() {
            // Use a Zipf distribution for clients activity
            // We assume all clients can use any service
            let mut weights: Vec<f64> = iter::repeat_n(1, network.users.len())
                .enumerate()
                .map(|(i,_)| 1./(i as f64))
                .collect();
            weights.shuffle(&mut rng);
            local_src_ip_users.insert(*s, (network.users.clone(), WeightedIndex::new(&weights).unwrap()));

            let mut weights: Vec<f64> = iter::repeat_n(1, network.servers.len())
                .enumerate()
                .map(|(i,_)| 1./(i as f64))
                .collect();
            weights.shuffle(&mut rng);
            local_src_ip_servers.insert(*s, (network.servers.clone(), WeightedIndex::new(&weights).unwrap()));

            let servers = network.servers_per_service.get(s).unwrap().clone();
            // Use a Zipf distribution for servers activity
            let mut weights: Vec<f64> = iter::repeat_n(1, servers.len())
                .enumerate()
                .map(|(i,_)| 1./(i as f64))
                .collect();
            weights.shuffle(&mut rng);
            local_dst_ip.insert(*s, (servers, WeightedIndex::new(&weights).unwrap()));
        }

        let mut local_ttl: HashMap<Ipv4Addr, u8> = HashMap::new();
        for ip in network.users.iter().chain(network.servers.iter()) {
            // TODO ! TTL should be calculated from the topology
            local_ttl.insert(*ip, 255);
        }

        let tl_extra_data = TransferLearningExtraData {
            local_src_ip_users,
            local_src_ip_servers,
            local_dst_ip,
            local_ttl,
            services_per_server: network.services_per_server.clone(),
        };

        // log::info!("{bn_common}");
        let mut model = BayesianModel {
            bn,
            bin_count,
            transfer_learning: Some(tl_extra_data),
        };

        model.apply_network(network)?;
        Ok(model)
    }

    pub fn from_source(m: &models::ModelsSource) -> Result<Self, String> {
        let bn_string: String = m
            .get_bn()
            .map_err(|e| format!("Cannot find the Bayesian networks: {e}"))?;

        log::trace!("Loading Bayesian network");
        let bif_common = bifxml::from_str(&bn_string)?;

        log::trace!("Converting from BIF");
        let (bn, bin_count) = bn_from_bif(bif_common)?;

        log::info!("Bayesian network has been loaded");

        // log::info!("{bn_common}");
        let mut model = BayesianModel {
            bn,
            bin_count,
            transfer_learning: None,
        };

        model.remove_impossible_values()?;
        Ok(model)
    }

    // Used to remove impossible values
    fn condition_cpt(&self, node: usize, index_parent: usize, parent_val: usize) -> CPT {
        let mut output: Vec<Option<WeightedIndex<f64>>> = vec![];
        assert!(
            self.bn.nodes[node].parents_cardinality[index_parent] > parent_val,
            "Parent val is too large: {parent_val}"
        );
        for (mut index_cpt, cpt) in self.bn.nodes[node].cpt.as_ref().unwrap().iter().enumerate() {
            for (index, card) in self.bn.nodes[node]
                .parents_cardinality
                .iter()
                .enumerate()
                .rev()
            {
                if index == index_parent {
                    if index_cpt % card == parent_val {
                        output.push(cpt.clone());
                    }
                    break;
                }
                index_cpt /= card;
            }
        }
        // log::info!("Initial CPT: {:?}", self.bn.nodes[node].cpt.as_ref().unwrap());
        // log::info!("Conditioned CPT: {output:?}");
        assert_eq!(
            self.bn.nodes[node].cpt.as_ref().unwrap().len() / output.len(),
            self.bn.nodes[node].parents_cardinality[index_parent]
        );
        output
    }

    // find the values of parents that only lead to "None" CPTs
    fn remove_impossible_values(&mut self) -> Result<(), String> {
        // log::info!("Remove impossible values");
        // traverse the network in reverse topological order
        // indeed, children can modify their parents’ CPT
        for index in (0..self.bn.nodes.len()).rev() {
            let node = &self.bn.nodes[index];
            // log::info!("{:?}", node.feature);
            let parents = node.parents.clone();
            let parents_card = node.parents_cardinality.clone();
            for (index_parent, parent) in parents.iter().enumerate() {
                // let mut removed: Vec<String> = vec![]; // only used for log
                for v in 0..parents_card[index_parent] {
                    // check each value of each parent
                    if self
                        .condition_cpt(index, index_parent, v)
                        .iter()
                        .all(Option::is_none)
                    // is there only None? Then we delete that value
                    {
                        // removed.push(self.bn.nodes[*parent].feature.get_value_string(v));
                        let parent = self.bn.nodes.get_mut(*parent).unwrap();
                        if !parent.removed_values.contains(&v) {
                            remove_value(parent, v)?;
                        }
                    }
                }
            }
        }
        for index in (0..self.bn.nodes.len()).rev() {
            let node = &self.bn.nodes[index];
            if !node.removed_values.is_empty() {
                log::debug!(
                    "Removed unnecessary values {:?} of {:?}",
                    node.removed_values
                        .iter()
                        .map(|v| node.feature.get_value_string(*v))
                        .collect::<Vec<String>>(),
                    node.feature
                );
            }
        }
        Ok(())
    }

    fn apply_network(&mut self, network: &network::Network) -> Result<(), String> {
        for node in self.bn.nodes.iter_mut() {
            match &mut node.feature {
                // we set the probability of absent services to 0
                Feature::L7Proto(v) => {
                    // get services present in the network
                    for s in network.services.iter() {
                        if !v.contains(s) {
                            log::warn!(
                                "Service {s:?} is not present in the original dataset and will not be generated"
                            );
                        }
                    }
                    // create a list of all the indices to set the probability to 0
                    let weight_update: Vec<(usize, &f64)> = v
                        .iter()
                        .enumerate()
                        .filter_map(|(index, proto)| {
                            if network.services.contains(proto) {
                                None
                            } else {
                                Some((index, &0.0f64))
                            }
                        })
                        .collect();
                    // modify all the probability distributions
                    for cpt in node.cpt.as_mut().unwrap().iter_mut() {
                        if let Some(weights) = cpt {
                            let result = weights.update_weights(&weight_update);
                            // log::error!("Valeur impossible après mise à jour des distributions");
                            if result.is_err() {
                                *cpt = None;
                            }
                        }
                    }
                }
                _ => (),
            }
        }

        self.remove_impossible_values()?;
        Ok(())
    }
}

fn bn_from_bif(
    network: bifxml::Network,
) -> Result<(BayesianNetwork, usize), String> {
    // Used only for computing the topological order
    struct TopologicalNode {
        parents: HashSet<String>,
        children: Vec<String>,
    }

    let mut processed_bn = BayesianNetwork { nodes: vec![] };

    // first, start computing the topological order
    let mut nodes: HashMap<String, TopologicalNode> = HashMap::new();
    let mut roots: Vec<String> = vec![];

    // convert def to TopologicalNode
    for (i, def) in network.definition.iter().enumerate() {
        assert_eq!(def.variable, network.variable[i].name);
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
        let children = nodes[&v].children.clone();
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
        let v = topo_order.remove(p);
        topo_order.insert(0, v); // insert at the start
    }

    // If "Src IP" (or similar) is present, is must be at the end of the list because its parents may change
    // Since it never has any children, the topological order will still be valid
    // for var_name in ["Src IP Addr", "Dst IP Addr", "Dst Pt"] {
    //     if let Some(p) = topo_order.iter().position(|s| s.as_str() == var_name) {
    //         let v = topo_order.remove(p);
    //         topo_order.push(v); // push at the end
    //     }
    // }

    // log::info!("Topological order: {topo_order:?}");

    let mut variable = vec![];
    let mut definition = vec![];
    for v in topo_order {
        for (index, var) in network.variable.iter().enumerate() {
            if var.name == v {
                variable.push(var.clone());
                definition.push(network.definition[index].clone());
                break;
            }
        }
    }

    // network = sorted_network;

    let mut var_names: Vec<String> = vec![];

    let mut bin_count: Option<usize> = None;

    for (v, def) in variable.iter().zip(definition) {
        assert_eq!(v.name, def.variable); // we assume the order is the same between
        // <variable> and <definition>

        // global index of parents
        let parents: Vec<usize> = def
            .given
            .clone()
            .unwrap_or(vec![])
            .into_iter()
            .map(|v| {
                var_names
                    .iter_mut()
                    .position(|s| s.as_str() == v)
                    .expect("Not in topological order!") // FIXME: change to Result
            })
            .collect();

        let cpt: CPT = def
            .table
            .split_ascii_whitespace()
            .map(|s| {
                let n = s.parse::<f64>().expect("Cannot parse the CPT");
                if n < 1e-9 { 0.0f64 } else { n } // we remove impossible combination with non-zero
                // probability due to the use of a prior
            })
            .collect::<Vec<_>>()
            .chunks(v.outcome.len())
            .map(|l| WeightedIndex::new(l).ok()) // some lines are only 0. In that case, insert a
            // None.
            .collect();

        // println!("{}", def.variable);
        // println!("{:?}", v.outcome);
        let feature: Option<Feature> = match v.name.as_str() {
            "Time" => {
                bin_count = Some(v.outcome.len());
                Some(Feature::TimeBin(v.outcome.len()))
            }
            "Cat Packet" => Some(Feature::PktCount(v.outcome.len())),
            "Src IP Role" => Some(Feature::SrcIpRole(
                v.outcome
                    .clone()
                    .into_iter()
                    .map(|s| IpRole::from_str(&s))
                    .collect::<Result<Vec<IpRole>, String>>()?,
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
                v.outcome
                    .clone()
                    .into_iter()
                    .map(|s| IpRole::from_str(&s))
                    .collect::<Result<Vec<IpRole>, String>>()?,
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
                v.outcome
                    .clone()
                    .into_iter()
                    .map(|s| L7Proto::from_str(&s).unwrap())
                    .collect(),
            )),
            "Proto" => Some(Feature::L4Proto(
                v.outcome
                    .clone()
                    .into_iter()
                    .map(|s| L4Proto::from_str(&s).unwrap())
                    .collect(),
            )),
            "Src TTL" => Some(Feature::SrcTTL(
                v.outcome
                    .clone()
                    .into_iter()
                    .map(|s| s[4..].parse::<u8>().unwrap_or(64))
                    .collect(),
            )),
            "Dst TTL" => Some(Feature::DstTTL(
                v.outcome
                    .clone()
                    .into_iter()
                    .map(|s| s[4..].parse::<u8>().unwrap_or(64)) // TODO: should be handled in the
                    // Bayesian network learning
                    .collect(),
            )),
            "Src MAC" => Some(Feature::SrcMac(
                v.outcome
                    .clone()
                    .into_iter()
                    .map(|s| MacAddr::from_str(&s).expect("Not a valid MAC address"))
                    .collect(),
            )),
            "Dst MAC" => Some(Feature::DstMac(
                v.outcome
                    .clone()
                    .into_iter()
                    .map(|s| MacAddr::from_str(&s).expect("Not a valid MAC address"))
                    .collect(),
            )),
            "Dst Pt" => Some(Feature::DstPt(
                v.outcome
                    .clone()
                    .into_iter()
                    .map(|s| {
                        if s == "unique" {
                            DstPt::Random
                        } else {
                            DstPt::Fixed(u16::from_str(s.strip_prefix("port-").unwrap()).unwrap())
                        }
                    })
                    .collect(),
            )),

            "Connection State" => Some(Feature::EndFlags(
                v.outcome
                    .clone()
                    .into_iter()
                    .map(|s| TCPConnState::from_str(&s))
                    .collect::<Result<Vec<TCPConnState>, String>>()?,
            )),

            _ => None, // some duplicated features are deliberately ignored (such as Dst Pt UDP/TCP)
        };

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
            // if matches!(feature, Feature::L7Proto(_)) {
            //     println!("{cpt:?}");
            // }
            let node = BayesianNetworkNode {
                feature,
                parents, // indices in the Bayesian network’s nodes
                parents_cardinality,
                cpt,
                removed_values: HashSet::new(),
            };
            processed_bn.nodes.push(node);
        }
        // }
    }

    Ok((processed_bn, bin_count.expect("Time feature not found!")))
}

impl BNGenerator {
    pub fn new(model: Arc<BayesianModel>, online: bool) -> Self {
        // TODO: adapter le modèle à la config du réseau !
        BNGenerator { model, online }
    }
}

impl Stage2 for BNGenerator {
    /// Generates flows
    fn generate_flows(
        &self,
        ts: SeededData<TimePoint>,
    ) -> Result<impl Iterator<Item = SeededData<Flow>>, String> {
        let mut rng = Pcg32::seed_from_u64(ts.seed);
        let mut domain_vector: IntermediateVector = IntermediateVector::default();
        let mut discrete_vector: Vec<usize> = vec![];

        let mut restart = true;
        while restart {
            restart = false;
            let time = min(
                self.model.bin_count - 1,
                ((ts.data.date_time.num_seconds_from_midnight() as f64 / (3600. * 24.)).fract()
                    * (self.model.bin_count as f64)) as usize,
            );
            discrete_vector.clear();
            discrete_vector.push(time);
            domain_vector = self.model.bn.sample(&mut rng, &mut discrete_vector)?;

            if domain_vector.src_ip == domain_vector.dst_ip {
                restart = true;
                continue;
            }

            domain_vector.timestamp = Some(ts.data.unix_time);
            let uniform = OS::Windows.get_ephemeral_port_distr(); // TODO: use the actual OS
            // Use the default source port for that protocol if that exists
            domain_vector.src_port = Some(match domain_vector.l7_proto.unwrap().get_default_src_port() {
                Port::Fixed(p) => p,
                Port::Random => uniform.sample(&mut rng)
            });

            if domain_vector.dst_port.is_none() {
                // Some protocol have random destination port, like FTP-data
                domain_vector.dst_port = Some(uniform.sample(&mut rng));
            }

            if let Some(ref tl) = self.model.transfer_learning {
                // Sample the destination IP
                domain_vector.dst_ip = Some(match domain_vector.dst_ip_role.unwrap() {
                    IpRole::User => unreachable!("User can never be destination"),
                    IpRole::Server => {
                        let (ips, weights) = tl.local_dst_ip.get(&domain_vector.l7_proto.unwrap()).unwrap();
                        *ips.get(weights.sample(&mut rng)).unwrap()
                    },
                    // TODO: take into account Internet servers from the config
                    IpRole::Internet => {
                        sample_random_global_ip(&mut rng)
                    },
                });

                domain_vector.src_ip = Some(match domain_vector.dst_ip_role.unwrap() {
                    IpRole::User => {
                        let (ips, weights) = tl.local_src_ip_users.get(&domain_vector.l7_proto.unwrap()).unwrap();
                        *ips.get(weights.sample(&mut rng)).unwrap()
                    }
                    IpRole::Server => {
                        let (ips, weights) = tl.local_src_ip_servers.get(&domain_vector.l7_proto.unwrap()).unwrap();
                        *ips.get(weights.sample(&mut rng)).unwrap()
                    },
                    // TODO: take into account Internet clients from the config
                    IpRole::Internet => {
                        sample_random_global_ip(&mut rng)
                    },
                });

                let port = tl.services_per_server.get(&(domain_vector.dst_ip.unwrap(), domain_vector.l7_proto.unwrap())).unwrap().first().unwrap().get_port();
                domain_vector.dst_port = Some(match port {
                    Port::Fixed(p) => p,
                    Port::Random => uniform.sample(&mut rng)
                });

                // Complete TTL
                domain_vector.src_ttl = Some(match domain_vector.src_ip_role.unwrap() {
                    // TODO: we can do better
                    IpRole::Internet => Uniform::new(52, 108).unwrap().sample(&mut rng),
                    _ => *tl.local_ttl.get(&domain_vector.src_ip.unwrap()).unwrap()
                });
                domain_vector.dst_ttl = Some(match domain_vector.dst_ip_role.unwrap() {
                    IpRole::Internet => Uniform::new(52, 108).unwrap().sample(&mut rng),
                    _ => *tl.local_ttl.get(&domain_vector.src_ip.unwrap()).unwrap()
                });

            }

        }
        Ok(iter::once(SeededData {
            seed: rng.next_u64(),
            data: domain_vector.into(),
        }))
    }
}
