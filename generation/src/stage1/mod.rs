use crate::structs::*;
use serde::Deserialize;
use std::fs::File;
use rand_pcg::Pcg32;
use rand::prelude::*;

/// A node of the Bayesian network
#[derive(Deserialize, Debug, Clone)]
struct BayesianNetworkNode {
    parents: Vec<usize>, // where to collect the data
    cpt: Vec<CptLine>
}

#[derive(Deserialize, Debug, Clone)]
struct CptLine {
    value: f32,
    probas: Vec<(i32,f32)>,
}

impl BayesianNetworkNode {
    /// Sample the value of one variable and update the vector with it
    fn sample(&self, vector: &mut Vec<i32>) {
        panic!("Not implemented");
    }

}

/// The possible values of the cells inside a pattern
#[derive(Deserialize, Debug, Clone)]
enum CellType {
    Fixed(u32),
    Free(BayesianNetworkNode),
    ReuseVariable(usize,usize) // values are the coordinates of the cell in the partial flows to reuse
}

#[derive(Deserialize, Debug, Clone)]
struct BayesianNetwork {
    graph: Vec<BayesianNetworkNode> // order is assumed to be topological
}

impl BayesianNetwork {
    /// Sample a vector from the Bayesian network
    fn sample(&self) -> Vec<i32> {
        panic!("Not implemented");
    }

}

/// Each pattern has partial flows and a Bayesian network that describes the distribution of "free" cells
#[derive(Deserialize, Debug, Clone)]
struct Pattern {
    weight: f32,
    start_ts_distrib: f32,
    partial_flows: Vec<Vec<CellType>>,
    bayesian_network: BayesianNetwork
}

#[derive(Deserialize, Debug, Clone)]
struct PatternSet {
    patterns: Vec<Pattern>,
    // metadata: PatternMetaData,
}

// #[derive(Deserialize, Debug, Clone)]
// struct PatternMetaData {
//     input_file: String,
//     creation_time: String,
// }


/// Stage 1: generates flow descriptions
pub struct Stage1 {
    set: PatternSet,
    rng: Pcg32,
}

impl Stage1 {

    pub fn new(seed: u64) -> Self {
        Stage1 { set: PatternSet { patterns: vec![] }, rng: Pcg32::seed_from_u64(seed) }
    }

    /// Import patterns from a file
    pub fn import_patterns(&mut self, filename: &str) -> std::io::Result<()> {
        let f = File::open(filename)?;
        let mut set : PatternSet = serde_json::from_reader(f)?;
        println!("Patterns {:?} are loaded",filename);
        self.set.patterns.append(&mut set.patterns);
        Ok(())
    }

    /// Generates flows. At least "number of flows" are generated (a difference of a few flows can be expected).
    pub fn generate_flows(&self, number_of_flows: u32) -> Vec<Flow> {
        panic!("Not implemented");
    }

}
