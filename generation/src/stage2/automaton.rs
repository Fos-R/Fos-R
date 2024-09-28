#![allow(unused)]

use crate::structs::*;
use crate::tcp::*;
use serde::Deserialize;
use rand::prelude::*;
use rand::distributions::WeightedIndex;
use rand::Rng;
use std::time::{Duration, Instant};
use rand_distr::{Normal, Distribution};

// Automaton are graphs. Graphs are not straightforward in Rust due to ownership, so we reference nodes by their index in the graph. Indices are never reused, leading to a small memory leak. Since we do not need to remove regularly nodes, it’s not a big deal.

// pub fn complete_tcp_with_values<R: Rng + ?Sized>(rng: &mut R, data: TCPPacketInfo) {
//     panic!("Not implemented");
// }

#[derive(Debug,Clone)]
struct TimedNode<T: EdgeType> {
    out_edges: Vec<TimedEdge<T>>,
}

#[derive(Debug,Clone)]
struct TimedEdge<T: EdgeType> {
    dst_node: usize,
    src_node: usize, // not sure if useful
    transition_proba: f32,
    data: Option<T>, // no data if transition to sink state
    mu: [f32; 2],
    cov: [[f32; 2]; 2],
}

impl<T: EdgeType> TimedEdge<T> {
    // https://en.wikipedia.org/wiki/Multivariate_normal_distribution#Conditional_distributions

    fn get_conditioned_mu(&self, size: f32) -> f32 {
        self.mu[0] + self.cov[0][1] / self.cov[1][1] * (size - self.mu[1])
    }

    fn get_conditioned_var(&self) -> f32 {
        self.cov[0][0] - self.cov[0][1] * self.cov[0][1] / self.cov[1][1]
    }
}

#[derive(Debug,Clone)]
pub struct TimedAutomaton<T: EdgeType> {
    graph: Vec<TimedNode<T>>,
    metadata: AutomatonMetaData,
    noise: Noise,
    initial_state: usize,
    accepting_state: usize
}

#[derive(Deserialize, Debug, Clone)]
struct AutomatonMetaData {
    select_dst_ports: Vec<u32>,
    ignore_dst_ports: Vec<u32>,
    input_file: String,
    creation_time: String,
}

#[derive(Deserialize, Debug, Clone)]
struct Noise {
    none: f32,
    deletion: f32,
    reemission: f32,
    transposition: f32,
    addition: f32,
}

struct ConstraintsNode<T: EdgeType> {
    out_edges: Vec<ConstraintsEdge<T>>,
}

struct ConstraintsEdge<T: EdgeType> {
    data: T,
}

pub struct ConstraintsAutomaton<T: EdgeType> {
    graph: Vec<ConstraintsNode<T>>
}

pub fn new_packet_number_constraints_automaton<T: EdgeType>(flow: &FlowData) -> ConstraintsAutomaton<T> {
    panic!("Not implemented");
}

pub fn new_tcp_flags_constraints_automaton(flow: &FlowData) -> ConstraintsAutomaton<TCPEdgeTuple> {
    panic!("Not implemented");
}

impl<T: EdgeType> TimedAutomaton<T> {

    pub fn intersect_automata(&self, constraints: &ConstraintsAutomaton<T>) -> TimedAutomaton<T> {
        panic!("Not implemented");
    }

    pub fn sample<R: Rng + ?Sized, U>(&self, rng: &mut R, initial_ts: Instant, header_creator: impl Fn(Payload, Instant, &T) -> U) -> Vec<U> {
        let mut output = vec![];
        let mut current_state = self.initial_state;
        let mut current_ts = initial_ts;
        while current_state != self.accepting_state {
            assert!(!self.graph[current_state].out_edges.is_empty());
            let mut weights = vec![];
            for e in self.graph[current_state].out_edges.iter() {
                weights.push(e.transition_proba);
            }
            let dist = WeightedIndex::new(&weights).unwrap();
            let e = &self.graph[current_state].out_edges[dist.sample(rng)];
            if let Some(data) = &e.data { // if $-transition, don’t create a header
                let (payload, payload_size) = match data.get_payload_type() {
                    PayloadType::Empty => (Payload::Empty, 0),
                    PayloadType::Random(sizes) => {
                        let size = sizes.choose(rng).unwrap().clone();
                        (Payload::Random(size), size)
                    },
                    PayloadType::Replay(tss) => {
                        let ts = tss.choose(rng).unwrap();
                        (Payload::Replay(ts.clone()), ts.len())
                    }
                };
                let mu = e.get_conditioned_mu(payload_size as f32);
                let var = e.get_conditioned_var();
                let normal = Normal::new(mu, var).unwrap();
                let iat = normal.sample(rng).max(0.); // TODO: add a small random positive delay
                current_state = e.dst_node;
                current_ts += Duration::from_millis(iat as u64);
                let data = header_creator(payload, current_ts, data);
                output.push(data);
            }
        }
        output
    }

}

// IMPORT FROM JSON

#[derive(Deserialize, Debug)]
pub struct JsonAutomaton {
    edges: Vec<JsonEdge>,
    noise: Noise,
    initial_state: usize,
    accepting_state: usize,
    pub protocol: JsonProtocol,
    metadata: AutomatonMetaData,
}

#[derive(Deserialize, Debug)]
struct JsonEdge {
    p: f32,
    src: usize,
    dst: usize,
    symbol: String,
    mu: Vec<f32>,
    cov: Vec<Vec<f32>>,
    tss: Vec<String>,
}

#[derive(Deserialize, Debug)]
pub enum JsonProtocol {
    TCP,
    UDP,
    ICMP
}

impl<T: EdgeType> TimedAutomaton<T> {
    pub fn import_timed_automaton(a: JsonAutomaton, symbol_parser: impl Fn(String, Vec<String>) -> T) -> Self {
        let mut nodes_nb = 0;
        let mut graph : Vec<TimedNode<T>> = vec![];
        for _ in 0..a.edges.len()+1 { // the automaton is connexe, so there #edges+1 >= #nodes
            graph.push(TimedNode { out_edges: vec![] });
        }
        for e in a.edges {
            let data =
                if e.symbol.find("$").is_some() {
                    None
                } else {
                    Some(symbol_parser(e.symbol, e.tss))
                };
            let new_edge = TimedEdge { dst_node: e.dst, src_node: e.src, transition_proba: e.p, data, mu: e.mu.try_into().unwrap(), cov: [[e.cov[0][0], e.cov[0][1]],[e.cov[1][0],e.cov[1][1]]] };
            graph[e.src].out_edges.push(new_edge);
            nodes_nb = nodes_nb.max(e.src+1).max(e.dst+1);
        }
        graph.truncate(nodes_nb);
        dbg!(&graph);
        TimedAutomaton::<T> { graph, metadata: a.metadata, noise: a.noise, initial_state: a.initial_state, accepting_state: a.accepting_state }
    }
}

