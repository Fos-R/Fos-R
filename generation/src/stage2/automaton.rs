use crate::structs::*;
use serde::Deserialize;
use std::time::Duration;
use std::cmp::max;

// Automaton are graphs. Graphs are not straightforward in Rust due to ownership, so we reference nodes by their index in the graph. Indices are never reused, leading to a small memory leak. Since we do not need to remove regularly nodes, it’s not a big deal.

struct TimedNode<T: Protocol> {
    out_edges: Vec<TimedEdge<T>>,
}

struct TimedEdge<T: Protocol> {
    dst_node: usize,
    src_node: usize, // not sure if useful
    transition_proba: f32,
    data: T,
    // expectation vector
    // covariance matrix
}

pub struct TimedAutomaton<T: Protocol> {
    graph: Vec<TimedNode<T>>
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

    fn intersect_automata(&self, constraints: &ConstraintsAutomaton<T>) -> TimedAutomaton<T> {
        panic!("Not implemented");
    }

    fn sample(&self) -> PacketsIR<T> {
        panic!("Not implemented");
    }

}

#[derive(Deserialize, Debug)]
pub struct JsonAutomaton {
    edges: Vec<JsonEdge>,
    noise: JsonNoise,
    initial_state: usize,
    accepting_state: usize,
    pub protocol: JsonProtocol,
    metadata: JsonMetaData,
}

#[derive(Deserialize, Debug)]
struct JsonNoise {
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
struct JsonMetaData {
    select_dst_ports: Vec<u32>,
    ignore_dst_ports: Vec<u32>,
    input_file: String,
    creation_time: String,
}

impl<T: Protocol> TimedAutomaton<T> {
    pub fn import_timed_automaton(a: JsonAutomaton, symbol_parser: impl Fn(String) -> T) -> Self {
        let mut nodes_nb = 0;
        for e in a.edges {
            nodes_nb = max(max(nodes_nb, e.src), e.dst);
        }
        let t = TimedAutomaton::<T> { graph: vec![] };
        t
    }
}

