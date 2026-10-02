use crate::network;
use crate::stage2::bn_structs::*;
use crate::stage2::{TCPConnState, bifxml};
use crate::structs::{DstIpRole, L4Proto, L7Proto, OS, SrcIpRole};
use crate::utils;

use pnet::util::MacAddr;
use rand_core::Rng;
use rand_distr::Distribution;
use rand_distr::Uniform;
use rand_distr::weighted::WeightedIndex;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt::{Display, Error, Formatter};
use std::iter;
use std::net::Ipv4Addr;
use std::str::FromStr;

const GIBBS_BURN_IN: usize = 10;
const GIBBS_GIVE_UP: usize = 100;

/// A node of the Bayesian network
#[derive(Debug, Clone)]
struct BayesianNetworkNode {
    feature: Feature,
    removed_values: HashSet<usize>,
    cpt: Option<CPT>,                // TimeBin has no CPT
    parents: Vec<usize>,             // indices in the Bayesian network’s nodes
    parents_cardinality: Vec<usize>, // the cardinality of each parents. Used to compute the index
    // in the cpt
    children: Vec<usize>,
    // Index of this node in the Bayesian network
    index: usize,
}

#[allow(clippy::upper_case_acronyms)]
/// A conditional probability table
type CPT = Vec<Option<WeightedIndex<f64>>>; // some combination may be impossible

impl BayesianNetworkNode {
    /// Get the line of the CPT corresponding to the current vector
    fn get_cpt_line(&self, current: &[usize]) -> Option<&WeightedIndex<f64>> {
        let mut parents_index = 0;
        for (index, card) in self.parents.iter().zip(self.parents_cardinality.iter()) {
            parents_index = parents_index * card + current[*index];
        }
        match &self.cpt {
            None => unreachable!(), // only happens with Time
            Some(cpt) => cpt[parents_index].as_ref(),
        }
    }

    /// Sample the value of one variable and update the vector with it
    fn sample_index(&self, rng: &mut impl Rng, current: &[usize]) -> Option<usize> {
        // TODO: check SrcIp != DstIp
        self.get_cpt_line(current).map(|w| w.sample(rng))
    }

    /// Return the probability of this node given its parents for the current values
    /// Used for computing the full conditional distribution
    fn get_probability(&self, current: &[usize]) -> f64 {
        // We assume that SrcIp is always just before DstIp
        // Check if Src IP == Dst IP
        if (matches!(self.feature, Feature::DstIp(_))
            && current[self.index] == current[self.index - 1])
            || (matches!(self.feature, Feature::SrcIp(_))
                && current[self.index] == current[self.index + 1])
        {
            0.0
        } else {
            self.get_cpt_line(current)
                .map(|w| w.weight(current[self.index]).unwrap() / w.total_weight())
                .unwrap_or(0.0)
        }
    }
}

#[derive(Debug, Clone)]
/// A Bayesian network, which is simply a collection of nodes in topological order
pub struct BayesianNetwork {
    nodes: Vec<BayesianNetworkNode>,
}

impl Display for BayesianNetwork {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        for (index, n) in self.nodes.iter().enumerate() {
            if n.parents.is_empty() {
                writeln!(f, "Node {index}: {:?}", n.feature)?;
            } else {
                writeln!(f, "Node {index}: {:?}, parents:", n.feature)?;
            }
            for p in &n.parents {
                writeln!(f, "   Node {p}: {:?}", self.nodes[*p].feature)?;
            }
        }
        Ok(())
    }
}

impl BayesianNetwork {

    pub fn is_time_bin_possible(&self, index: usize) -> bool {
        // TimeBin is always
        assert!(matches!(self.nodes[0].feature, Feature::TimeBin(_)));
        self.nodes[0].removed_values.contains(&index)
    }

    /// Sample a vector from the Bayesian network
    /// We use a Bayesian network learned for this network, so it should
    pub fn sample_in_domain(
        &self,
        rng: &mut impl Rng,
        discrete_vector: Vec<usize>,
    ) -> Result<IntermediateVector, String> {
        // println!("{self:?}";
        let mut try_again = true;
        let mut rejected: u64 = 0;
        let mut new_discrete_vector = discrete_vector.clone();
        while try_again {
            try_again = false;
            new_discrete_vector.clone_from(&discrete_vector);
            for v in &self.nodes {
                // log::info!("Sampling {:?} (index: {index})", v.feature);
                // println!("Discrete vector: {:?}", new_discrete_vector);
                if !matches!(v.feature, Feature::TimeBin(_)) {
                    let index = v.sample_index(rng, &new_discrete_vector);
                    if let Some(i) = index {
                        assert!(i < v.feature.get_cardinality());
                        // println!("Sampled value for {:?}: {}", v.feature, i);
                        new_discrete_vector.push(i);
                    } else {
                        // log::error!("Rejected");
                        rejected += 1;
                        if rejected > 10000 {
                            return Err("Too many rejections during sampling.".to_string());
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
        let domain_vector = self.discrete_to_domain(new_discrete_vector, rng);
        Ok(domain_vector)
    }

    /// Sample a vector from the Bayesian network
    pub fn sample_transfer_learning(
        &self,
        rng: &mut impl Rng,
        mut discrete_vector: Vec<usize>,
    ) -> Result<IntermediateVector, String> {
        // println!("{self:?}");
        for v in &self.nodes {
            if !matches!(v.feature, Feature::TimeBin(_)) {
                // TODO: avoid creating Uniform for just one value, better use Rng::random_range
                // If there is no possible value (due to constraints in the BN), select a random one
                // It will be later be fixed with the Gibbs sampling
                let i = v.sample_index(rng, &discrete_vector).unwrap_or(
                    Uniform::new(0, v.feature.get_cardinality())
                        .unwrap()
                        .sample(rng),
                );
                assert!(i < v.feature.get_cardinality());
                discrete_vector.push(i);
            }
        } // if it’s "Time", do not push any value (it was already done previously)
        // Iterate over the vector using Gibbs sampling
        self.gibbs_sampling(rng, &mut discrete_vector);
        let domain_vector = self.discrete_to_domain(discrete_vector, rng);
        Ok(domain_vector)
    }

    fn discrete_to_domain(
        &self,
        discrete_vector: Vec<usize>,
        rng: &mut impl Rng,
    ) -> IntermediateVector {
        let mut domain_vector: IntermediateVector = IntermediateVector::default();
        for (v_index, v) in self.nodes.iter().enumerate() {
            if !matches!(v.feature, Feature::TimeBin(_)) {
                let i = discrete_vector[v_index];
                match &v.feature {
                    Feature::SrcOs(v) => domain_vector.src_os = Some(v[i]),
                    Feature::DstOs(v) => domain_vector.dst_os = Some(v[i]),
                    Feature::SrcIpRole(v) => domain_vector.src_ip_role = Some(v[i]),
                    Feature::DstIpRole(v) => domain_vector.dst_ip_role = Some(v[i]),
                    Feature::SrcTTL(v) => domain_vector.src_ttl = Some(v[i]),
                    Feature::DstTTL(v) => domain_vector.dst_ttl = Some(v[i]),
                    Feature::SrcMac(v) => domain_vector.src_mac = Some(v[i]),
                    Feature::DstMac(v) => domain_vector.dst_mac = Some(v[i]),
                    Feature::L7Proto(v) => domain_vector.l7_proto = Some(v[i]),
                    Feature::SrcIp(v) => match v[i] {
                        AnonymizedIpv4Addr::Known(p) => domain_vector.src_ip = Some(p),
                        AnonymizedIpv4Addr::Public => {
                            domain_vector.src_ip = Some(utils::sample_random_global_ip(rng));
                        }
                    },
                    Feature::DstIp(v) => match v[i] {
                        AnonymizedIpv4Addr::Known(p) => domain_vector.dst_ip = Some(p),
                        AnonymizedIpv4Addr::Public => {
                            domain_vector.dst_ip = Some(utils::sample_random_global_ip(rng));
                        }
                    },
                    Feature::DstPt(v) => match v[i] {
                        DstPt::Random => domain_vector.dst_port = None,
                        DstPt::Fixed(p) => domain_vector.dst_port = Some(p),
                    },
                    Feature::PktCount(_) => domain_vector.packets_count_cluster = Some(i),
                    Feature::L4Proto(v) => domain_vector.proto = Some(v[i]),
                    Feature::EndFlags(v) => domain_vector.tcp_flags = Some(v[i]),
                    Feature::TimeBin(_) => unreachable!(), // by construction
                }
            }
        }
        domain_vector
    }

    /// Perform a Gibbs sampling from an already initialized vector
    fn gibbs_sampling(&self, rng: &mut impl Rng, discrete_vector: &mut [usize]) {
        // println!("Starting Gibbs");
        let mut current_iter = 0;
        let mut all_good = false;
        while (current_iter < GIBBS_BURN_IN || !all_good) && current_iter < GIBBS_GIVE_UP {
            // println!("{current_iter}");
            current_iter += 1;
            all_good = true;
            for (v_index, v) in self.nodes.iter().enumerate() {
                if !matches!(v.feature, Feature::TimeBin(_)) {
                    // println!("Generating value for {:?}", v.feature);
                    let mut weights: Vec<f64> = vec![];
                    for value in 0..v.feature.get_cardinality() {
                        // Get the full conditional probability of "value"
                        discrete_vector[v_index] = value;
                        let mut w = v.get_probability(discrete_vector);
                        for ch in &v.children {
                            w *= self.nodes[*ch].get_probability(discrete_vector);
                        }
                        weights.push(w);
                    }
                    // println!("{:?}", weights);
                    let distr = WeightedIndex::new(weights);
                    if let Ok(distr) = distr {
                        discrete_vector[v_index] = distr.sample(rng);
                    } else {
                        // println!("No possible value for {:?}", v.feature);
                        // no possible value! use a random one
                        discrete_vector[v_index] = Uniform::new(0, v.feature.get_cardinality())
                            .unwrap()
                            .sample(rng);
                        all_good = false;
                    }
                } // Do not modify the Time
            }
        }
        // println!("End of Gibbs");
    }

    // Used to remove impossible values
    fn condition_cpt(&self, node: usize, index_parent: usize, parent_val: usize) -> CPT {
        let mut output: Vec<Option<WeightedIndex<f64>>> = vec![];
        assert!(
            self.nodes[node].parents_cardinality[index_parent] > parent_val,
            "Parent val is too large: {parent_val}"
        );
        for (mut index_cpt, cpt) in self.nodes[node].cpt.as_ref().unwrap().iter().enumerate() {
            for (index, card) in self.nodes[node]
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
        // log::info!("Initial CPT: {:?}", self.nodes[node].cpt.as_ref().unwrap());
        // log::info!("Conditioned CPT: {output:?}");
        assert_eq!(
            self.nodes[node].cpt.as_ref().unwrap().len() / output.len(),
            self.nodes[node].parents_cardinality[index_parent]
        );
        output
    }

    // find the values of parents that only lead to "None" CPTs
    pub fn remove_impossible_values(&mut self) -> Result<(), String> {
        log::trace!("Remove impossible values");
        // traverse the network in reverse topological order
        // indeed, children can modify their parents’ CPT
        for index in (0..self.nodes.len()).rev() {
            let node = &self.nodes[index];
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
                        // removed.push(self.nodes[*parent].feature.get_value_string(v));
                        let parent = self.nodes.get_mut(*parent).unwrap();
                        if !parent.removed_values.contains(&v) {
                            remove_value(parent, v)?;
                        }
                    }
                }
            }
        }
        for index in (0..self.nodes.len()).rev() {
            let node = &self.nodes[index];
            if !node.removed_values.is_empty() {
                log::info!(
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

    pub fn update_probabilities(&mut self, network: &network::Network) {
        for node in &mut self.nodes {
            // we set the probability of absent OS to 0
            if let Feature::SrcOs(v) = &mut node.feature {
                // get OS present in the network
                for s in &network.present_os {
                    if !v.contains(s) {
                        log::warn!(
                            "OS {s:?} is not present in the train set and will not be generated"
                        );
                    }
                }
                // create a list of all the indices to set the probability to 0
                let weight_update: Vec<(usize, &f64)> = v
                    .iter()
                    .enumerate()
                    .filter_map(|(index, os)| {
                        if network.present_os.contains(os) {
                            None
                        } else {
                            Some((index, &0.0))
                        }
                    })
                    .collect();
                // modify all the probability distributions
                for cpt in node.cpt.as_mut().unwrap() {
                    if let Some(weights) = cpt {
                        let result = weights.update_weights(&weight_update);
                        // log::error!("Valeur impossible après mise à jour des distributions");
                        if result.is_err() {
                            *cpt = None;
                        }
                    }
                }
            }
            // we set the probability of absent services to 0
            else if let Feature::L7Proto(v) = &mut node.feature {
                // get services present in the network
                for s in &network.services {
                    if !v.contains(s) {
                        log::warn!(
                            "Service {s:?} is not present in the train set and will not be generated"
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
                            Some((index, &0.0))
                        }
                    })
                    .collect();
                // modify all the probability distributions
                for cpt in node.cpt.as_mut().unwrap() {
                    if let Some(weights) = cpt {
                        let result = weights.update_weights(&weight_update);
                        // log::error!("Valeur impossible après mise à jour des distributions");
                        if result.is_err() {
                            *cpt = None;
                        }
                    }
                }
            } else if !network.has_internet_access
                && let Feature::SrcIpRole(v) = &mut node.feature
            {
                // No internet access? Then set the probability of the Internet role to
                // zero
                let weight_update: Vec<(usize, &f64)> = v
                    .iter()
                    .enumerate()
                    .filter_map(|(index, role)| {
                        if role == &SrcIpRole::Internet {
                            Some((index, &0.0))
                        } else {
                            None
                        }
                    })
                    .collect();
                // modify all the probability distributions
                for cpt in node.cpt.as_mut().unwrap() {
                    if let Some(weights) = cpt {
                        let result = weights.update_weights(&weight_update);
                        // log::error!("Valeur impossible après mise à jour des distributions");
                        if result.is_err() {
                            *cpt = None;
                        }
                    }
                }
            } else if !network.has_internet_access
                && let Feature::DstIpRole(v) = &mut node.feature
            {
                // Same for DstIpRole
                let weight_update: Vec<(usize, &f64)> = v
                    .iter()
                    .enumerate()
                    .filter_map(|(index, role)| {
                        if role == &DstIpRole::Internet {
                            Some((index, &0.0))
                        } else {
                            None
                        }
                    })
                    .collect();
                // modify all the probability distributions
                for cpt in node.cpt.as_mut().unwrap() {
                    if let Some(weights) = cpt {
                        let result = weights.update_weights(&weight_update);
                        // log::error!("Valeur impossible après mise à jour des distributions");
                        if result.is_err() {
                            *cpt = None;
                        }
                    }
                }
            }
        }
    }

    pub fn add_tl_nodes(
        &mut self,
        src_ip: HashMap<(L7Proto, OS, SrcIpRole), AnonymizedIpv4Distr>,
        dst_ip: HashMap<(L7Proto, OS, DstIpRole), AnonymizedIpv4Distr>,
        all_ips: &[Ipv4Addr],
    ) {
        let all_ips: Vec<AnonymizedIpv4Addr> = all_ips
            .iter()
            .map(|ip| AnonymizedIpv4Addr::Known(*ip))
            // add Internet
            .chain(iter::once(AnonymizedIpv4Addr::Public))
            .collect();

        let feature = Feature::SrcIp(all_ips.clone());

        let index_l7proto = self
            .nodes
            .iter()
            .position(|n| matches!(n.feature, Feature::L7Proto(_)))
            .unwrap();

        {
            let index_src_os = self
                .nodes
                .iter()
                .position(|n| matches!(n.feature, Feature::SrcOs(_)))
                .unwrap();
            let index_src_ip_role = self
                .nodes
                .iter()
                .position(|n| matches!(n.feature, Feature::SrcIpRole(_)))
                .unwrap();

            let parents = vec![index_l7proto, index_src_os, index_src_ip_role];
            let parents_cardinality = vec![
                self.nodes[index_l7proto].feature.get_cardinality(),
                self.nodes[index_src_os].feature.get_cardinality(),
                self.nodes[index_src_ip_role].feature.get_cardinality(),
            ];
            let mut cpt: CPT = vec![];
            // The order of the variables in the for loops must be the same as in the "parents" vector

            if let Feature::L7Proto(ref services) = self.nodes[index_l7proto].feature {
                for s in services {
                    if let Feature::SrcOs(ref os_domain) = self.nodes[index_src_os].feature {
                        for os in os_domain {
                            if let Feature::SrcIpRole(ref roles) =
                                self.nodes[index_src_ip_role].feature
                            {
                                for role in roles {
                                    if let Some((domain, distr)) = src_ip.get(&(*s, *os, *role)) {
                                        let v: Vec<f64> = all_ips
                                            .iter()
                                            .map(|ip| {
                                                match domain.iter().position(|ip2| ip == ip2) {
                                                    None => 0., // this value cannot be generated for this combination
                                                    Some(p) => distr.weight(p).unwrap(), // get the associated weight
                                                }
                                            })
                                            .collect();
                                        cpt.push(Some(WeightedIndex::new(v).unwrap()));
                                    } else {
                                        cpt.push(None);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            assert_eq!(cpt.len(), parents_cardinality.iter().product::<usize>());

            let node = BayesianNetworkNode {
                feature,
                parents,
                parents_cardinality,
                children: vec![], // no children
                cpt: Some(cpt),
                removed_values: HashSet::new(),
                index: self.nodes.len(),
            };
            self.nodes.push(node);
        }

        {
            let feature = Feature::DstIp(all_ips.clone());

            let index_dst_os = self
                .nodes
                .iter()
                .position(|n| matches!(n.feature, Feature::DstOs(_)))
                .unwrap();
            let index_dst_ip_role = self
                .nodes
                .iter()
                .position(|n| matches!(n.feature, Feature::DstIpRole(_)))
                .unwrap();

            let parents = vec![index_l7proto, index_dst_os, index_dst_ip_role];
            let parents_cardinality = vec![
                self.nodes[index_l7proto].feature.get_cardinality(),
                self.nodes[index_dst_os].feature.get_cardinality(),
                self.nodes[index_dst_ip_role].feature.get_cardinality(),
            ];
            let mut cpt: CPT = vec![];

            if let Feature::L7Proto(ref services) = self.nodes[index_l7proto].feature {
                for s in services {
                    if let Feature::DstOs(ref os_domain) = self.nodes[index_dst_os].feature {
                        for os in os_domain {
                            if let Feature::DstIpRole(ref roles) =
                                self.nodes[index_dst_ip_role].feature
                            {
                                for role in roles {
                                    if let Some((domain, distr)) = dst_ip.get(&(*s, *os, *role)) {
                                        let v: Vec<f64> = all_ips
                                            .iter()
                                            .map(|ip| {
                                                match domain.iter().position(|ip2| ip == ip2) {
                                                    None => 0., // this value cannot be generated for this combination
                                                    Some(p) => distr.weight(p).unwrap(), // get the associated weight
                                                }
                                            })
                                            .collect();
                                        cpt.push(Some(WeightedIndex::new(v).unwrap()));
                                    } else {
                                        cpt.push(None);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            assert_eq!(cpt.len(), parents_cardinality.iter().product::<usize>());

            let node = BayesianNetworkNode {
                feature,
                parents,
                parents_cardinality,
                children: vec![], // no children
                cpt: Some(cpt),
                removed_values: HashSet::new(),
                index: self.nodes.len(),
            };
            self.nodes.push(node);
        }

        assert!(matches!(
            self.nodes[self.nodes.len() - 1].feature,
            Feature::DstIp(_)
        ));
        assert!(matches!(
            self.nodes[self.nodes.len() - 2].feature,
            Feature::SrcIp(_)
        ));
    }

    // fn identify_possible_values(&mut self) -> Result<(), String> {
    //     // TODO: also verify which conn_state / automata combination is possible
    //     let mut m = selen::prelude::Model::default();
    //     Ok(())
    // }
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
        for cpt in cpt {
            if let Some(weights) = cpt {
                let result = weights.update_weights(&[(index, &0.0)]);
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

pub fn bn_from_bif(
    network: bifxml::Network,
    alpha: u64,
) -> Result<(BayesianNetwork, usize), String> {
    assert!(alpha >= 1); // by default, a pseudo-count is already included

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

    for def in &network.definition {
        if let Some(given) = &def.given {
            for v in given {
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
            .map(|s| s.parse::<u64>().expect("Cannot parse the CPT"))
            .map(|l| if l == 0 { 0.0 } else { (l + alpha - 1) as f64 }) // leave zeros as is
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
            "Src OS" => Some(Feature::SrcOs(
                v.outcome
                    .clone()
                    .into_iter()
                    .map(|s| OS::from_str(&s).map_err(|e| format!("Unknown OS: {e} for {s}")))
                    .collect::<Result<Vec<OS>, String>>()?,
            )),
            "Dst OS" => Some(Feature::DstOs(
                v.outcome
                    .clone()
                    .into_iter()
                    .map(|s| OS::from_str(&s).map_err(|e| format!("Unknown OS: {e} for {s}")))
                    .collect::<Result<Vec<OS>, String>>()?,
            )),
            "Src IP Role" => Some(Feature::SrcIpRole(
                v.outcome
                    .clone()
                    .into_iter()
                    .map(|s| SrcIpRole::from_str(&s))
                    .collect::<Result<Vec<SrcIpRole>, String>>()?,
            )),
            "Src IP Addr" => Some(Feature::SrcIp(
                v.outcome
                    .clone()
                    .into_iter()
                    .map(|v| match v.parse().ok() {
                        Some(ip) => AnonymizedIpv4Addr::Known(ip),
                        None => AnonymizedIpv4Addr::Public,
                    })
                    .collect(),
            )),
            "Dst IP Role" => Some(Feature::DstIpRole(
                v.outcome
                    .clone()
                    .into_iter()
                    .map(|s| DstIpRole::from_str(&s))
                    .collect::<Result<Vec<DstIpRole>, String>>()?,
            )),
            "Dst IP Addr" => Some(Feature::DstIp(
                v.outcome
                    .clone()
                    .into_iter()
                    .map(|v| match v.parse().ok() {
                        Some(ip) => AnonymizedIpv4Addr::Known(ip),
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

            _ => None, // TODO: panic ? error message ?
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
            let node = BayesianNetworkNode {
                feature,
                parents, // indices in the Bayesian network’s nodes
                parents_cardinality,
                children: vec![],
                cpt,
                removed_values: HashSet::new(),
                index: processed_bn.nodes.len(),
            };
            processed_bn.nodes.push(node);
        }
        // }
    }

    for i in 0..processed_bn.nodes.len() {
        for p in &processed_bn.nodes[i].parents.clone() {
            processed_bn.nodes[*p].children.push(i);
        }
    }

    Ok((processed_bn, bin_count.expect("Time feature not found!")))
}
