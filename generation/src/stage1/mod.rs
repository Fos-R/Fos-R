#![allow(unused)]

use crate::structs::*;
use serde::Deserialize;
use std::fs::File;
use rand_pcg::Pcg32;
use rand::prelude::*;
use std::time::Duration;
use std::sync::Arc;

/// A node of the Bayesian network
#[derive(Deserialize, Debug, Clone)]
struct BayesianNetworkNode {
    feature_number: usize,
    partial_flow_number: usize,
    parents: Vec<usize>, // indices in the Bayesian network’s nodes
    cpt: Vec<CptLine>
}

#[derive(Deserialize, Debug, Clone)]
#[serde(tag = "type")]
enum CptLine {
    Discrete {  weights: Vec<f32>,
                values: Vec<u32>,
                parents_values: Vec<u32> }, // value of the parents, as ordered in the "parents" field of BayesianNetworkNode
    Interval {  weights: Vec<f32>,
                values: Vec<(u32,u32)>,
                parents_values: Vec<u32> },
    Normal {
                mean: f32,
                variance: f32,
                parents_values: Vec<u32> },
}

impl BayesianNetworkNode {
    /// Sample the value of one variable and update the vector with it
    fn sample(&self, vector: &mut Vec<i32>) {
        panic!("Not implemented");
    }
}

/// The possible values of the cells inside a pattern
#[derive(Deserialize, Debug, Clone)]
#[serde(tag = "type")]
enum CellType {
    Fixed { value: u32 },
    Free,
    ReuseVariable { col: usize, row: usize } // values are the coordinates of the cell in the partial flows to reuse
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
    start_ts_distrib: f32,
    partial_flows: Vec<Vec<CellType>>,
    bayesian_network: BayesianNetwork
}

#[derive(Deserialize, Debug, Clone)]
pub struct PatternSet {
    weights: Vec<u32>,
    patterns: Vec<Pattern>,
    default_pattern: BayesianNetwork,
    metadata: PatternMetaData,
}

#[derive(Deserialize, Debug, Clone)]
struct PatternMetaData {
    input_file: String,
    creation_time: String,
}

/// Stage 1: generates flow descriptions
pub struct Stage1 {
    set: Arc<PatternSet>,
}

impl Stage1 {

    pub fn new(patterns: Arc<PatternSet>) -> Self {
        Stage1 { set: patterns }
    }

    /// Generates flows
    pub fn generate_flows(&self, ts: SeededData<Duration>) -> Vec<SeededData<Flow>> {
        vec![] // TODO
    }

}

/// Import patterns from a file
pub fn import_patterns(filename: &str) -> std::io::Result<PatternSet> {
    let f = File::open(filename)?;
    let set : PatternSet = serde_json::from_reader(f)?;
    println!("Patterns {:?} are loaded",filename);
    Ok(set)
}
