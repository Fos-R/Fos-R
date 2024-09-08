use crate::structs::*;
use std::collections::HashMap;

/// Number of columns in the flow description
const COLUMNS_NUMBER: usize = 5; // TODO: verify the value

/// A node of the Bayesian network
struct BayesianNetworkNode {
    parents: Vec<usize>, // where to collect the data
    cpt: HashMap<Vec<i32>, Vec<(i32,f32)>>
}

impl BayesianNetworkNode {
    /// Sample the value of one variable and update the vector with it
    fn sample(&self, vector: &mut Vec<i32>) {
        panic!("Not implemented");
    }

}

/// The possible values of the cells inside a pattern
enum CellType {
    Fixed(u32),
    Free(BayesianNetworkNode),
    ReuseVariable(usize,usize) // values are the coordinates of the cell in the partial flows to reuse
}

struct BayesianNetwork {
    graph: Vec<BayesianNetworkNode> // order is assumed to be topological
}

impl BayesianNetwork {
    /// Sample a vector from the Bayesian network
    fn sample(&self) -> Vec<i32> {
        panic!("Not implemented");
    }

}

/// Each pattern has a partial flow and a Bayesian network that describes the distribution of "free" cells
struct Pattern {
    partial_flows: Vec<[CellType; COLUMNS_NUMBER]>,
    bayesian_network: BayesianNetwork
}

/// Stage 1: generates flow descriptions
pub struct Stage1 {
    patterns: Vec<Pattern>
}

impl Stage1 {

    pub fn new() -> Self {
        Stage1 { patterns: vec![] }
    }

    /// Import patterns from a file
    pub fn import_patterns(&mut self, filename: &str) -> Self {
        panic!("Not implemented");
    }

    /// Generates flows. At least "number of flows" are generated (a difference of a few flows can be expected).
    pub fn generate_flows(&self, number_of_flows: u32) -> Vec<Flow> {
        panic!("Not implemented");
    }

}
