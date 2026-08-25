//! Topology Generator

use std::fs;
use std::path::Path;

use microlp::{ComparisonOp, OptimizationDirection, Problem, Variable};

use crate::topo::config::GenerationParameters;
use crate::topo::sub_topology::SubTopology;

/// Tree node for representing topology hierarchies
#[derive(Debug, Clone)]
pub struct TreeNode {
    value: String,
    children: Vec<TreeNode>,
}

impl TreeNode {
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            children: Vec::new(),
        }
    }

    pub fn value(&self) -> &str {
        &self.value
    }

    pub fn children(&self) -> &[TreeNode] {
        &self.children
    }

    pub fn add_child(&mut self, child: TreeNode) {
        self.children.push(child);
    }

    pub fn remove_child(&mut self, index: usize) {
        self.children.remove(index);
    }

    /// Recursively print the tree (for debugging)
    pub fn print(&self, indent: usize) {
        let prefix = "  ".repeat(indent);
        println!("{}node value: {}", prefix, self.value);
        println!("{}children:", prefix);
        for child in &self.children {
            child.print(indent + 1);
        }
    }
}

/// Topology generator that creates network topologies based on constraints
pub struct TopologyGenerator {
    /// Parameters from the last generation run
    last_topo_generation_parameters: Option<GenerationParameters>,
    /// Interface to virtualization, provides available sub-topologies
    sub_topologies: Vec<SubTopology>,
    /// List of generated topologies
    /// Each topology is a list of sub-topologies
    topologies: Vec<Vec<SubTopology>>,
    /// List of generated topology trees
    topology_trees: Vec<TreeNode>,
    /// Global variables for tree generation
    root: Option<TreeNode>,
}

impl TopologyGenerator {
    pub fn new(sub_topologies: Vec<SubTopology>) -> Self {
        Self {
            last_topo_generation_parameters: None,
            sub_topologies,
            topologies: Vec::new(),
            topology_trees: Vec::new(),
            root: None,
        }
    }

    /// Generate a topology according to the given parameters: select the sub-topologies with the LP, then build every depth-limited tree over them
    pub fn generate_topologies(
        &mut self,
        topo_generation_parameters: &GenerationParameters,
    ) -> Result<Vec<SubTopology>, String> {
        self.last_topo_generation_parameters = Some(topo_generation_parameters.clone());

        // The candidate pool is the list of sub-topologies the generator was built with
        let topology = Self::solve_with_microlp(&self.sub_topologies, topo_generation_parameters)?;

        // Build one tree over the selected sub-topologies, exactly `tree_depth` levels when possible
        if let Some(tree) = Self::generate_tree(
            format!("{topology:?}"),
            &topology,
            topo_generation_parameters.tree_depth,
        ) {
            self.save_tree_if_unique(tree);
        }
        self.root = self.topology_trees.first().cloned();

        // Record the topology so `dump_topologies_specifications` can serialize it
        self.topologies.push(topology.clone());

        Ok(topology)
    }

    /// Solve the constraint problem using microlp
    fn solve_with_microlp(
        candidates: &[SubTopology],
        params: &GenerationParameters,
    ) -> Result<Vec<SubTopology>, String> {
        // Machines + the router of each sub-topology.
        let node_count = |st: &SubTopology| st.nodes.len() + 1;

        // Each sub-topology owns exactly one subnet, so a single count constraint covers both minimums
        let min_count = params.minimum_sub_topology.max(params.minimum_subnet_count);

        if candidates.is_empty() {
            return Err("no candidate sub-topologies to select from".to_string());
        }
        if min_count == 0 && params.minimum_node_count == 0 && params.services.is_empty() {
            return Err("generation parameters describe an empty topology".to_string());
        }
        if min_count > candidates.len() {
            return Err(format!(
                "need at least {min_count} sub-topologies, but only {} candidates exist",
                candidates.len()
            ));
        }

        let mut problem = Problem::new(OptimizationDirection::Minimize);

        // One variable per candidate
        let vars: Vec<Variable> = candidates
            .iter()
            .map(|_| problem.add_binary_var(1.0))
            .collect();

        // sum(x_i) >= min_count
        let count_expr: Vec<(Variable, f64)> = vars.iter().map(|&v| (v, 1.0)).collect();
        problem.add_constraint(count_expr, ComparisonOp::Ge, min_count as f64);

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
            .map_err(|e| format!("no topology satisfies the generation parameters: {e:?}"))?;

        let mut selected: Vec<usize> = vars
            .iter()
            .enumerate()
            .filter(|&(_, &v)| solution[v] > 0.5)
            .map(|(i, _)| i)
            .collect();

        let is_feasible = |sel: &[usize]| {
            sel.len() >= min_count
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

        while !is_feasible(&selected) {
            // Add the smallest candidate not yet selected
            let next = (0..candidates.len())
                .filter(|i| !selected.contains(i))
                .min_by_key(|&i| node_count(&candidates[i]));
            match next {
                Some(i) => selected.push(i),
                None => return Err("could not assemble a feasible topology".to_string()),
            }
        }

        Ok(selected
            .into_iter()
            .map(|i| candidates[i].clone())
            .collect())
    }

    /// Build one valid tree
    fn generate_tree(label: String, nodes: &[SubTopology], max_depth: usize) -> Option<TreeNode> {
        if nodes.is_empty() || max_depth == 0 {
            return None;
        }

        let depth = max_depth.min(nodes.len());
        let chain_len = depth - 1;
        let leaves = &nodes[chain_len..];

        // Build the chain bottom-up, the deepest chain node carries the leaves
        let mut subtree: Option<TreeNode> = None;
        for node in nodes[..chain_len].iter().rev() {
            let mut parent = TreeNode::new(format!("{:?}", node));
            match subtree {
                Some(child) => parent.add_child(child),
                None => {
                    for leaf in leaves {
                        parent.add_child(TreeNode::new(format!("{:?}", leaf)));
                    }
                }
            }
            subtree = Some(parent);
        }

        let mut root = TreeNode::new(label);
        match subtree {
            Some(chain_top) => root.add_child(chain_top),
            None => {
                // depth == 1 so every node is a direct child of the root
                for leaf in leaves {
                    root.add_child(TreeNode::new(format!("{:?}", leaf)));
                }
            }
        }
        Some(root)
    }

    /// Save a tree if it's unique
    fn save_tree_if_unique(&mut self, root: TreeNode) {
        let exists = self
            .topology_trees
            .iter()
            .any(|t| self.same_trees(t, &root));

        if !exists {
            self.topology_trees.push(root);
            println!("tree added, total: {}", self.topology_trees.len());
        } else {
            println!("same trees");
        }
    }

    /// Check if two trees are the same
    fn same_trees(&self, root1: &TreeNode, root2: &TreeNode) -> bool {
        if root1.value() != root2.value() {
            return false;
        }

        let nodes1 = root1.children();
        let nodes2 = root2.children();

        if nodes1.len() != nodes2.len() {
            return false;
        }

        for i in 0..nodes1.len() {
            if !self.same_trees(&nodes1[i], &nodes2[i]) {
                return false;
            }
        }

        true
    }

    /// Get the list of generated topologies
    pub fn get_generated_topologies(&self) -> &Vec<Vec<SubTopology>> {
        &self.topologies
    }

    /// Get the list of generated topology trees
    pub fn get_generated_topologies_trees(&self) -> &Vec<TreeNode> {
        &self.topology_trees
    }

    /// Dump all generated topologies specifications to the given directory
    pub fn dump_topologies_specifications(&self, path: &Path) -> std::io::Result<()> {
        println!(
            "-{} topologies specs will be dumped into: {:?}",
            self.topologies.len(),
            path
        );

        fs::create_dir_all(path)?;

        for (count, t) in self.topologies.iter().enumerate() {
            // Convert topology to JSON string
            let topology_json = serde_json::to_string_pretty(t)?;

            // Write to file
            let file_path = path.join(format!("topology_{}.json", count));
            fs::write(file_path, topology_json)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::topo::config::{GenerationParameters, Service, SubTopologyParameters};
    use crate::topo::sub_topology::SubTopology;

    #[test]
    fn test_tree_operations() {
        let mut tree = TreeNode::new("root");
        tree.add_child(TreeNode::new("child1"));
        tree.add_child(TreeNode::new("child2"));

        assert_eq!(tree.children().len(), 2);
        assert_eq!(tree.value(), "root");
    }

    /// st1: 3 machines + 1 router = 4 nodes, provides cloud_storage
    const ST1_YAML: &str = r#"
mask: 24
name: st1
nodes:
- ip: 192.168.0.1
  name: r1_1
  type: router
- ip: 192.168.0.2
  name: n1_2
  os: linux
  type: machine
- ip: 192.168.0.3
  name: n1_3
  os: linux
  services: cloud_storage
  type: machine
- ip: 192.168.0.4
  name: n1_4
  os: windows
  type: machine
subnet: 192.168.0.0
"#;

    /// st2: 2 machines + 1 router = 3 nodes, provides ftp_server
    const ST2_YAML: &str = r#"
mask: 24
name: st2
nodes:
- ip: 192.168.1.1
  name: r2_1
  type: router
- ip: 192.168.1.2
  name: n2_2
  os: linux
  services: ftp_server
  type: machine
- ip: 192.168.1.3
  name: n2_3
  os: windows
  type: machine
subnet: 192.168.1.0
"#;

    /// st3: 1 machine + 1 router = 2 nodes, provides web_server
    const ST3_YAML: &str = r#"
mask: 24
name: st3
nodes:
- ip: 192.168.2.1
  name: r3_1
  type: router
- ip: 192.168.2.2
  name: n3_2
  os: linux
  services: web_server
  type: machine
subnet: 192.168.2.0
"#;

    fn sub_topology_from_yaml(config: &str) -> SubTopology {
        let parameters: SubTopologyParameters =
            serde_yaml::from_str(config).expect("Failed to parse sub topology config");
        SubTopology::new(parameters).expect("Failed to build sub topology")
    }

    fn generation_params_from_yaml(config: &str) -> GenerationParameters {
        serde_yaml::from_str(config).expect("Failed to parse generation config")
    }

    /// Pool: st1 (4 nodes, cloud_storage), st2 (3 nodes, ftp_server), st3 (2 nodes, web_server)
    fn test_pool() -> Vec<SubTopology> {
        vec![
            sub_topology_from_yaml(ST1_YAML),
            sub_topology_from_yaml(ST2_YAML),
            sub_topology_from_yaml(ST3_YAML),
        ]
    }

    #[test]
    fn test_generate_topologies_from_yaml_configs() {
        let params = generation_params_from_yaml(
            r#"
minimum_sub_topology: 2
minimum_node_count: 5
minimum_subnet_count: 2
tree_depth: 2

services:
  - ftp_server
  - cloud_storage
"#,
        );

        let mut generator = TopologyGenerator::new(test_pool());
        let topology = generator
            .generate_topologies(&params)
            .expect("topology generation should succeed");

        // Only st1 provides cloud_storage and only st2 provides ftp_server, and together they satisfy every minimum: the LP must pick exactly these two.
        assert_eq!(topology.len(), 2);
        assert!(topology.iter().any(|st| st.name == "st1"));
        assert!(topology.iter().any(|st| st.name == "st2"));

        // Hard minimums hold
        assert!(topology.len() >= params.minimum_sub_topology);
        let total_nodes: usize = topology.iter().map(|st| st.nodes.len() + 1).sum();
        assert!(total_nodes >= params.minimum_node_count);

        // Every required service is covered
        assert!(
            topology
                .iter()
                .any(|st| st.contains_service(&Service::FtpServer))
        );
        assert!(
            topology
                .iter()
                .any(|st| st.contains_service(&Service::CloudStorage))
        );

        // The topology is recorded for dumping...
        assert_eq!(generator.get_generated_topologies().len(), 1);

        // ...and trees were generated (tree_depth = 2 allows two levels)
        assert!(!generator.get_generated_topologies_trees().is_empty());

        // The result serializes to JSON (exercises the Serialize derives)
        let json = serde_json::to_string_pretty(&topology).expect("topology should serialize");
        assert!(json.contains("st1"));
        assert!(json.contains("ftp_server"));
    }

    #[test]
    fn test_generate_topologies_node_minimum_forces_wider_selection() {
        // st1 + st2 = 7 nodes < 8, so the LP relaxation selects st3 only fractionally (0.5) and the greedy repair has to add it for real
        let params = generation_params_from_yaml(
            r#"
minimum_sub_topology: 2
minimum_node_count: 8
minimum_subnet_count: 2
tree_depth: 1

services:
  - ftp_server
"#,
        );

        let mut generator = TopologyGenerator::new(test_pool());
        let topology = generator
            .generate_topologies(&params)
            .expect("topology generation should succeed");

        assert_eq!(topology.len(), 3);
        let total_nodes: usize = topology.iter().map(|st| st.nodes.len() + 1).sum();
        assert!(total_nodes >= params.minimum_node_count);
    }

    #[test]
    fn test_generate_topologies_infeasible_parameters() {
        // A service no candidate provides
        let missing_service = generation_params_from_yaml(
            r#"
minimum_sub_topology: 1
minimum_node_count: 1
minimum_subnet_count: 1
tree_depth: 1

services:
  - dns_server
"#,
        );

        let mut generator = TopologyGenerator::new(test_pool());
        let err = generator
            .generate_topologies(&missing_service)
            .expect_err("generation should fail: nobody provides dns_server");
        assert!(err.contains("no candidate sub-topology"));

        // More sub-topologies than the pool has (the generator can be reused: failed runs leave no state behind)
        let too_many = generation_params_from_yaml(
            r#"
minimum_sub_topology: 10
minimum_node_count: 1
minimum_subnet_count: 1
tree_depth: 1

services: []
"#,
        );

        let err = generator
            .generate_topologies(&too_many)
            .expect_err("generation should fail: not enough candidates");
        assert!(err.contains("need at least 10"));
    }

    #[test]
    fn test_generate_topologies_zero_tree_depth_builds_no_trees() {
        let params = generation_params_from_yaml(
            r#"
minimum_sub_topology: 2
minimum_node_count: 5
minimum_subnet_count: 2
tree_depth: 0

services:
  - ftp_server
  - cloud_storage
"#,
        );

        let mut generator = TopologyGenerator::new(test_pool());
        let topology = generator
            .generate_topologies(&params)
            .expect("topology generation should succeed");

        // The topology is still selected and recorded...
        assert_eq!(topology.len(), 2);
        assert_eq!(generator.get_generated_topologies().len(), 1);

        // ...but depth 0 allows no level, so no tree is generated
        assert!(generator.get_generated_topologies_trees().is_empty());
    }

    struct Rng(u64);

    impl Rng {
        fn new(seed: u64) -> Self {
            Self(seed)
        }

        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
            z ^ (z >> 31)
        }

        /// Inclusive range [min, max].
        fn gen_range(&mut self, min: usize, max: usize) -> usize {
            debug_assert!(min <= max);
            min + (self.next_u64() % ((max - min + 1) as u64)) as usize
        }

        fn gen_bool(&mut self) -> bool {
            self.next_u64() & 1 == 0
        }

        fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
            &items[self.gen_range(0, items.len() - 1)]
        }
    }

    /// All service names as they appear in YAML (snake_case)
    const SERVICE_NAMES: &[&str] = &[
        "web_server",
        "ftp_server",
        "mail_server",
        "cloud_storage",
        "log_server",
        "dbms_server",
        "cms_server",
        "proxy_server",
        "ldap_server",
        "dns_server",
        "ssh_server",
    ];

    const OS_NAMES: &[&str] = &["linux", "windows"];

    /// Print a tree with compact labels (sub-topology names instead of the full `Debug` dump stored in each node value)
    fn print_tree_compact(node: &TreeNode, indent: usize) {
        let prefix = "  ".repeat(indent);
        let value = node.value();
        let label = if value.starts_with('[') {
            "<topology root>".to_string()
        } else if let Some(start) = value.find("name: \"") {
            let rest = &value[start + "name: \"".len()..];
            let end = rest.find('"').unwrap_or(rest.len());
            rest[..end].to_string()
        } else {
            value.to_string()
        };
        println!("{prefix}{label}");
        for child in node.children() {
            print_tree_compact(child, indent + 1);
        }
    }

    #[test]
    fn test_generate_topologies_randomized() {
        // Seed from the clock, or from FOSR_TEST_SEED for reproducibility
        let seed = std::env::var("FOSR_TEST_SEED")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or_else(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() ^ u64::from(d.subsec_nanos()))
                    .unwrap_or(42)
            });
        println!("seed: {seed} (rerun with FOSR_TEST_SEED={seed} to reproduce)");
        let mut rng = Rng::new(seed);

        // Build a random candidate pool as raw YAML strings
        let pool_size = rng.gen_range(200, 250);
        let mut pool = Vec::new();
        let mut pool_yamls: Vec<String> = Vec::new();
        let mut pool_services: Vec<&'static str> = Vec::new();

        println!("\n=== candidate pool ({pool_size} sub-topologies) ===");
        for i in 0..pool_size {
            let machine_count = rng.gen_range(2, 5);
            let mut yaml = format!(
                "mask: 24\nname: st{i}\nnodes:\n- ip: 10.0.{i}.1\n  name: r{i}_1\n  type: router\n"
            );
            let mut services_here: Vec<&str> = Vec::new();

            for m in 0..machine_count {
                let os = rng.pick(OS_NAMES);
                yaml.push_str(&format!(
                    "- ip: 10.0.{i}.{}\n  name: n{i}_{}\n  os: {os}\n",
                    m + 2,
                    m + 2
                ));
                // The first machine always hosts a service (guarantees the pool provides at least one), the others get one with 50% chance
                if m == 0 || rng.gen_bool() {
                    let service = rng.pick(SERVICE_NAMES);
                    yaml.push_str(&format!("  services: {service}\n"));
                    services_here.push(service);
                    if !pool_services.contains(service) {
                        pool_services.push(service);
                    }
                }
                yaml.push_str("  type: machine\n");
            }
            yaml.push_str(&format!("subnet: 10.0.{i}.0\n"));

            println!(
                "  st{i}: 10.0.{i}.0/24, {} nodes, services: {}",
                machine_count + 1,
                services_here.join(", ")
            );

            let parameters: SubTopologyParameters =
                serde_yaml::from_str(&yaml).expect("Failed to parse sub topology config");
            pool.push(SubTopology::new(parameters).expect("Failed to build sub topology"));
            pool_yamls.push(yaml);
        }

        // Derive generation parameters that are feasible by construction: minimums within pool bounds, required services drawn from the
        // services actually present in the pool
        let min_st = rng.gen_range(2, 3);
        let total_nodes: usize = pool.iter().map(|st| st.nodes.len() + 1).sum();
        let min_nodes = rng.gen_range(min_st * 2, total_nodes);

        let required_count = rng.gen_range(1, pool_services.len().min(2));
        let mut available = pool_services.clone();
        let mut required: Vec<&str> = Vec::new();
        for _ in 0..required_count {
            let i = rng.gen_range(0, available.len() - 1);
            required.push(available.swap_remove(i));
        }

        let services_yaml: String = required.iter().map(|s| format!("  - {s}\n")).collect();
        let params_yaml = format!(
            "minimum_sub_topology: {min_st}\nminimum_node_count: {min_nodes}\nminimum_subnet_count: {min_st}\ntree_depth: 5\n\nservices:\n{services_yaml}"
        );
        println!("\n=== generation parameters ===\n{params_yaml}");

        let params: GenerationParameters =
            serde_yaml::from_str(&params_yaml).expect("Failed to parse generation config");

        // Run the generator and dump the results
        let mut generator = TopologyGenerator::new(pool);
        let topology = generator
            .generate_topologies(&params)
            .expect("randomized generation should succeed (feasible by construction)");

        println!("\n=== config used for this run ===\n{params_yaml}");
        println!("--- candidate pool ---");
        for (i, y) in pool_yamls.iter().enumerate() {
            println!("--- st{i} ---\n{y}");
        }

        println!(
            "\n=== selected topology ({} sub-topologies) ===",
            topology.len()
        );
        let report = serde_json::json!({ "config": &params, "topology": &topology });
        println!(
            "\n=== run report ===\n{}",
            serde_json::to_string_pretty(&report).expect("report should serialize")
        );

        let trees = generator.get_generated_topologies_trees();
        println!("\n=== {} unique trees (showing up to 3) ===", trees.len());
        for (i, tree) in trees.iter().take(3).enumerate() {
            println!("--- tree {i} ---");
            print_tree_compact(tree, 0);
        }

        // Loose sanity checks (the draw is random, so assert the contract, not exact values)
        assert!(topology.len() >= params.minimum_sub_topology);
        let selected_nodes: usize = topology.iter().map(|st| st.nodes.len() + 1).sum();
        assert!(selected_nodes >= params.minimum_node_count);
        for service in &params.services {
            assert!(topology.iter().any(|st| st.contains_service(service)));
        }
        assert!(!trees.is_empty());
    }

    #[test]
    fn test_generate_tree_exact_depth() {
        let pool = test_pool();

        let tree = TopologyGenerator::generate_tree("root".to_string(), &pool, 2).expect("a tree");
        assert_eq!(tree.children().len(), 1);
        assert_eq!(tree.children()[0].children().len(), 2);

        let tree = TopologyGenerator::generate_tree("root".to_string(), &pool, 10).expect("a tree");
        let mut depth = 0;
        let mut node = &tree;
        while let Some(child) = node.children().first() {
            depth += 1;
            node = child;
        }
        assert_eq!(depth, 3);

        assert!(TopologyGenerator::generate_tree("root".to_string(), &pool, 0).is_none());
    }
}
