use crate::structs::*;
use serde::Deserialize;
use std::cmp::max;
use rand::prelude::*;
use rand::distributions::WeightedIndex;
use rand::Rng;

// Automaton are graphs. Graphs are not straightforward in Rust due to ownership, so we reference nodes by their index in the graph. Indices are never reused, leading to a small memory leak. Since we do not need to remove regularly nodes, it’s not a big deal.

struct TimedNode<T: Protocol> {
    out_edges: Vec<TimedEdge<T>>,
}

struct TimedEdge<T: Protocol> {
    dst_node: usize,
    src_node: usize, // not sure if useful
    transition_proba: f32,
    data: T,
    mu: Vec<f32>, // TODO: find a better type
    cov: Vec<Vec<f32>> // TODO: find a better type
}

pub struct TimedAutomaton<T: Protocol> {
    graph: Vec<TimedNode<T>>,
    metadata: MetaData,
    noise: Noise,
    initial_state: usize,
    accepting_state: usize
}

struct ConstraintsNode<T: Protocol> {
    out_edges: Vec<ConstraintsEdge<T>>,
}

struct ConstraintsEdge<T: Protocol> {
    data: T,
}

struct ConstraintsAutomaton<T: Protocol> {
    graph: Vec<ConstraintsNode<T>>
}

impl<T: Protocol> ConstraintsAutomaton<T> {
    fn new_packet_number_constraints_automaton(flow: &Flow) -> ConstraintsAutomaton<T> {
        panic!("Not implemented");
    }
}

impl ConstraintsAutomaton<TCPPacketInfo> {
    fn new_tcp_flags_constraints_automaton(flow: &Flow) -> ConstraintsAutomaton<TCPPacketInfo> {
        panic!("Not implemented");
    }
}

impl<T: Protocol> TimedAutomaton<T> {

    pub fn intersect_automata(&self, constraints: &ConstraintsAutomaton<T>) -> TimedAutomaton<T> {
        panic!("Not implemented");
    }

    pub fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Vec<T> {
        let mut output = vec![];
        let mut current_state = self.initial_state;
        while current_state != self.accepting_state {
            assert!(!self.graph[current_state].out_edges.is_empty());
            let mut weights = vec![];
            for e in self.graph[current_state].out_edges.iter() {
                weights.push(e.transition_proba);
            }
            let dist = WeightedIndex::new(&weights).unwrap();
            let nb = dist.sample(rng);
            current_state = self.graph[current_state].out_edges[nb].dst_node;
            output.push(self.graph[current_state].out_edges[nb].data);
            dbg!(current_state);
        }
        output
    }

}

#[derive(Deserialize, Debug)]
pub struct JsonAutomaton {
    edges: Vec<JsonEdge>,
    noise: Noise,
    initial_state: usize,
    accepting_state: usize,
    pub protocol: JsonProtocol,
    metadata: MetaData,
}

#[derive(Deserialize, Debug)]
struct Noise {
    none: f32,
    deletion: f32,
    reemission: f32,
    transposition: f32,
    addition: f32,
}

#[derive(Deserialize, Debug)]
struct JsonEdge {
    p: f32,
    src: usize,
    dst: usize,
    symbol: String,
    mu: Vec<f32>,
    cov: Vec<Vec<f32>>,
}

#[derive(Deserialize, Debug)]
pub enum JsonProtocol {
    TCP,
    UDP,
    ICMP
}

#[derive(Deserialize, Debug)]
struct MetaData {
    select_dst_ports: Vec<u32>,
    ignore_dst_ports: Vec<u32>,
    input_file: String,
    creation_time: String,
}

impl<T: Protocol> TimedAutomaton<T> {
    pub fn import_timed_automaton(a: JsonAutomaton, symbol_parser: impl Fn(String) -> T) -> Self {
        let mut nodes_nb = 0;
        let mut graph : Vec<TimedNode<T>> = vec![];
        for _ in 0..a.edges.len()+1 { // the automaton is connexe, so there #edges+1 >= #nodes
            graph.push(TimedNode { out_edges: vec![] });
        }
        for e in a.edges {
            let new_edge = TimedEdge { dst_node: e.dst, src_node: e.src, transition_proba: e.p, data: symbol_parser(e.symbol), mu: e.mu, cov: e.cov };
            graph[e.src].out_edges.push(new_edge);
            nodes_nb = max(max(nodes_nb, e.src+1), e.dst+1);
        }
        graph.truncate(nodes_nb);
        TimedAutomaton::<T> { graph, metadata: a.metadata, noise: a.noise, initial_state: a.initial_state, accepting_state: a.accepting_state }
    }
}

