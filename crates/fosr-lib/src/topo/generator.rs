//! Topology Generator

use microlp::{ComparisonOp, OptimizationDirection, Problem, Variable};
use rand::Rng;
use rand::SeedableRng;
use rand_pcg::Pcg32;
use std::collections::HashSet;
use std::net::Ipv4Addr;

use crate::topo::config::GenerationParameters;
use crate::topo::subtopo::{SubTopology, SubTopologyNode, SubTopologyOrInternet};
use crate::utils;

/// Tree for representing topology hierarchies
#[derive(Debug, Clone)]
struct TopologyTree {
    nodes: Vec<TopologyTreeNode>,
}

impl TopologyTree {
    fn new(value: SubTopologyOrInternet) -> Self {
        let root = TopologyTreeNode {
            value,
            assigned: HashSet::new(),
            children: Vec::new(),
            depth: 0,
        };
        Self { nodes: vec![root] }
    }

    fn into_subtopology_list(self) -> Vec<SubTopologyOrInternet> {
        self.nodes.into_iter().map(|n| n.value).collect()
    }

    fn add_child(
        &mut self,
        parent: usize,
        mut child: SubTopologyOrInternet,
        rng: &mut impl Rng,
    ) -> (usize, usize) {
        // In fact, only the root can be internet
        assert!(matches!(child, SubTopologyOrInternet::SubTopo(_)));
        if let SubTopologyOrInternet::SubTopo(ref mut t) = child {
            let interco = match self.nodes[parent].value {
                SubTopologyOrInternet::Internet => utils::sample_random_global_ip(rng),
                SubTopologyOrInternet::SubTopo(ref p) => {
                    let ip = alloc_ip_in_subnet(p, &self.nodes[parent].assigned).unwrap();
                    self.nodes[parent].assigned.insert(ip);
                    ip
                }
            };

            if let SubTopologyNode::Router(router) = &mut t.router_node {
                router.interco_address = interco;
            }
        }
        let child = TopologyTreeNode {
            value: child,
            children: vec![],
            assigned: HashSet::new(),
            depth: self.nodes[parent].depth + 1,
        };
        self.nodes.push(child);
        let index = self.nodes.len() - 1;
        self.nodes[parent].children.push(index);
        (
            self.nodes[parent].children.len(),
            self.nodes[parent].depth + 1,
        )
    }
}

/// Tree node for representing topology hierarchies
#[derive(Debug, Clone)]
struct TopologyTreeNode {
    value: SubTopologyOrInternet,
    assigned: HashSet<Ipv4Addr>, // extra IP assigned for children
    children: Vec<usize>,
    depth: usize,
}

/// Generate a topology according to the given parameters
pub fn generate_topology(
    sub_topologies: &[SubTopology],
    topo_generation_parameters: &GenerationParameters,
) -> Result<Vec<SubTopologyOrInternet>, String> {
    // The candidate pool is the list of sub-topologies the generator was built with
    let topology = solve_with_microlp(sub_topologies, topo_generation_parameters)?;

    generate_tree(topology, !topo_generation_parameters.no_internet_access)
}

/// Solve the constraint problem using microlp
fn solve_with_microlp(
    candidates: &[SubTopology],
    params: &GenerationParameters,
) -> Result<Vec<SubTopology>, String> {
    // Machines + the router of each sub-topology.
    let node_count = |st: &SubTopology| st.nodes.len() + 1;
    let is_topo_public = |st: &SubTopology| i32::from(st.is_public());

    if candidates.is_empty() {
        return Err("no candidate sub-topologies to select from".to_string());
    }
    if params.minimum_sub_topology == 0
        && params.minimum_node_count == 0
        && params.services.is_empty()
    {
        return Err("generation parameters describe an empty topology".to_string());
    }
    if params.minimum_sub_topology > candidates.len() {
        return Err(format!(
            "need at least {} sub-topologies, but only {} candidates exist",
            params.minimum_sub_topology,
            candidates.len()
        ));
    }

    let mut problem = Problem::new(OptimizationDirection::Minimize);

    if let Some(time_limit) = params.time_limit {
        problem.set_time_limit(time_limit);
    }

    // One variable per candidate
    let vars: Vec<Variable> = candidates
        .iter()
        .map(|_| problem.add_binary_var(1.0))
        .collect();

    if params.no_internet_access {
        // TODO: simplifier: retirer des candidats ceux qui ont un subnet public
        let public_expr: Vec<(Variable, f64)> = vars
            .iter()
            .zip(candidates)
            .map(|(&v, st)| (v, f64::from(is_topo_public(st))))
            .collect();

        problem.add_constraint(
            public_expr,
            ComparisonOp::Eq,
            0.0, // exactly 0
        );
    }

    // sum(x_i) >= params.minimum_sub_topology
    let count_expr: Vec<(Variable, f64)> = vars.iter().map(|&v| (v, 1.0)).collect();
    problem.add_constraint(
        count_expr,
        ComparisonOp::Ge,
        params.minimum_sub_topology as f64,
    );

    // sum(nodes_i * x_i) >= minimum_node_count
    let nodes_expr: Vec<(Variable, f64)> = vars
        .iter()
        .zip(candidates)
        .map(|(&v, st)| (v, node_count(st) as f64))
        .collect();
    problem.add_constraint(
        nodes_expr,
        ComparisonOp::Ge,
        params.minimum_node_count as f64,
    );

    // Each required service must appear on at least one selected sub-topology
    for service in &params.services {
        let coverage: Vec<(Variable, f64)> = vars
            .iter()
            .zip(candidates)
            .filter(|(_, st)| st.contains_service(service))
            .map(|(&v, _)| (v, 1.0))
            .collect();
        if coverage.is_empty() {
            return Err(format!("no candidate sub-topology provides {service:?}"));
        }
        problem.add_constraint(coverage, ComparisonOp::Ge, 1.0);
    }

    let solution = problem
        .solve()
        .map_err(|e| format!("no topology satisfies the generation parameters: {e:?}"))?
        .into_solution()
        .unwrap();

    let selected: Vec<usize> = vars
        .iter()
        .enumerate()
        .filter(|&(_, &v)| solution[v] > 0.5)
        .map(|(i, _)| i)
        .collect();

    let is_feasible = |sel: &[usize]| {
        sel.len() >= params.minimum_sub_topology
            && sel
                .iter()
                .map(|&i| node_count(&candidates[i]))
                .sum::<usize>()
                >= params.minimum_node_count
            && params
                .services
                .iter()
                .all(|s| sel.iter().any(|&i| candidates[i].contains_service(s)))
    };
    assert!(is_feasible(&selected));

    Ok(selected
        .into_iter()
        .map(|i| candidates[i].clone())
        .collect())
}

/// Build one valid tree
fn generate_tree(
    mut nodes: Vec<SubTopology>,
    internet_access: bool,
) -> Result<Vec<SubTopologyOrInternet>, String> {
    if nodes.is_empty() {
        return Err("No subnet selected!".to_string());
    }

    // max depth is the minimum depth to be sure that everything fit, + 1
    let max_depth = ((nodes.len() + 1) as f64).log2().ceil() as usize;

    let max_children_n = 2;

    // put subnet with public IP at the end of the Vec
    nodes.sort_by_key(super::subtopo::SubTopology::is_public);

    let mut tree = if internet_access {
        // Internet access: the root is the Internet
        TopologyTree::new(SubTopologyOrInternet::Internet)
    } else {
        // no Internet access: the root is a subtopo
        // we know there is at least one node
        TopologyTree::new(SubTopologyOrInternet::SubTopo(nodes.pop().unwrap()))
    };

    let mut rng = Pcg32::seed_from_u64(12345);
    let mut available_parents: Vec<usize> = vec![0];
    let mut child_index = 1;

    while let Some(node) = nodes.pop() {
        if available_parents.is_empty() {
            return Err("Maximum depth is too small".to_string());
        }
        let child = SubTopologyOrInternet::SubTopo(node);
        let parent_index = (rng.next_u32() as usize) % available_parents.len();
        let parent = available_parents[parent_index];
        let (children_n, child_depth) = tree.add_child(parent, child, &mut rng);
        if children_n >= max_children_n {
            available_parents.remove(parent_index);
        }
        if child_depth < max_depth {
            available_parents.push(child_index);
        }
        child_index += 1;
    }
    Ok(tree.into_subtopology_list())
}

fn node_address(node: &SubTopologyNode) -> Ipv4Addr {
    match node {
        SubTopologyNode::Machine(m) => m.address,
        SubTopologyNode::Router(r) => r.address,
    }
}

/// Allocate the first free host address in `parent`'s subnet
fn alloc_ip_in_subnet(
    parent: &SubTopology,
    assigned: &HashSet<Ipv4Addr>,
) -> Result<Ipv4Addr, String> {
    if !(8..=30).contains(&parent.mask) {
        return Err(format!(
            "subnet {}/{}: mask outside the supported 8..=30 range",
            parent.subnet, parent.mask
        ));
    }
    let host_bits = 32 - parent.mask as u32;
    let network = u32::from(parent.subnet) & (u32::MAX << host_bits);
    let size = 1u64 << host_bits;

    // Addresses already taken: machines, the router's LAN address, and interco addresses of previously processed siblings
    let mut used: HashSet<Ipv4Addr> = assigned.clone();
    for node in &parent.nodes {
        used.insert(node_address(node));
    }
    used.insert(node_address(&parent.router_node));

    // Usable host range: exclude the network and broadcast addresses
    for offset in 1..(size - 1) {
        let candidate = Ipv4Addr::from((u64::from(network) + offset) as u32);
        if !used.contains(&candidate) {
            return Ok(candidate);
        }
    }
    Err(format!(
        "no free address left in subnet {}/{}",
        parent.subnet, parent.mask
    ))
}
