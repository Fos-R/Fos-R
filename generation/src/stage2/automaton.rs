#![allow(unused)]

use crate::structs::*;
use crate::tcp::*;
use serde::Deserialize;
use rand::prelude::*;
use rand::distributions::WeightedIndex;
use rand::Rng;
use std::time::Duration;
use rand_distr::{Normal, Poisson, Distribution};

// Automaton are graphs. Graphs are not straightforward in Rust due to ownership, so we reference nodes by their index in the graph. Indices are never reused, leading to a small memory leak. Since we do not need to remove regularly nodes, it’s not a big deal.

// pub fn complete_tcp_with_values<R: Rng + ?Sized>(rng: &mut R, data: TCPPacketInfo) {
//     panic!("Not implemented");
// }

#[derive(Debug,Clone)]
struct TimedNode<T: EdgeType> {
    out_edges: Vec<TimedEdge<T>>,
}

#[derive(Debug,Clone)]
enum EdgeDistribution {
    Normal, // TODO: add cond_var to compute it only once
    Poisson
}

#[derive(Debug,Clone)]
struct TimedEdge<T: EdgeType> {
    dst_node: usize,
    src_node: usize, // not sure if useful
    transition_proba: f32,
    data: Option<T>, // no data if transition to sink state
    mu: [f32; 2],
    cov: [[f32; 2]; 2],
    p: EdgeDistribution,
}

impl EdgeDistribution {
    // https://en.wikipedia.org/wiki/Multivariate_normal_distribution#Conditional_distributions

    fn sample<R: Rng + ?Sized>(&self, rng: &mut R, cond_mu: f32, cond_var: f32) -> f32 {
        match &self {
            EdgeDistribution::Normal => {
                let normal = Normal::new(cond_mu, cond_var.sqrt()).unwrap();
                normal.sample(rng).max(0.)
            },
            EdgeDistribution::Poisson => {
                let poisson = Poisson::new((cond_mu + cond_var)/2.0).unwrap();
                poisson.sample(rng).max(0.)
            }
        }
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
    select_dst_ports: Vec<u16>,
    ignore_dst_ports: Vec<u16>,
    input_file: String,
    creation_time: String,
    automaton_name: String,
}

#[derive(Deserialize, Debug, Clone)]
struct Noise {
    none: f32,
    deletion: f32,
    reemission: f32,
    transposition: f32,
    addition: f32,
}

impl<T: EdgeType> TimedAutomaton<T> {

    pub fn is_compatible_with(&self, port: u16) -> bool {
        self.metadata.select_dst_ports.contains(&port)
    }

    pub fn get_name(&self) -> &str {
        &self.metadata.automaton_name
    }

    pub fn sample<R: Rng + ?Sized, U>(&self, rng: &mut R, initial_ts: Duration, header_creator: impl Fn(Payload, NoiseType, Duration, &T) -> U) -> Vec<U> {
        let mut output = vec![];
        let mut current_state = self.initial_state;
        let mut current_ts = initial_ts;
        // TODO: sample with noise
        while current_state != self.accepting_state {
            assert!(!self.graph[current_state].out_edges.is_empty());
            let mut weights = vec![];
            for e in self.graph[current_state].out_edges.iter() {
                weights.push(e.transition_proba);
            }
            // println!("{:?} {:?}",weights, self.graph[current_state].out_edges);
            let dist = WeightedIndex::new(&weights).unwrap();
            let e = &self.graph[current_state].out_edges[dist.sample(rng)];
            if let Some(data) = &e.data { // if $-transition, don’t create a header
                let (payload, payload_size) = match data.get_payload_type() {
                    PayloadType::Empty => (Payload::Empty, 0),
                    PayloadType::Random(sizes) => {
                        let size = sizes.choose(rng).unwrap().clone();
                        (Payload::Random(size), size)
                    },
                    PayloadType::Text(tss) => { // TODO
                        let ts = tss.choose(rng).unwrap();
                        (Payload::Replay(ts.clone().into()), ts.len())
                    }
                    PayloadType::Replay(tss) => {
                        let ts = tss.choose(rng).unwrap();
                        (Payload::Replay(ts.clone()), ts.len())
                    }
                };
                let cond_mu = e.mu[0] + e.cov[0][1] / e.cov[1][1] * (payload_size as f32 - e.mu[1]);
                let cond_var = e.cov[0][0] - e.cov[0][1] * e.cov[0][1] / e.cov[1][1];
                let iat = e.p.sample(rng, cond_mu, cond_var);
                current_ts += Duration::from_micros(iat as u64);
                let data = header_creator(payload, NoiseType::None, current_ts, data);
                output.push(data);
            }
            current_state = e.dst_node;
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
    payloads: JsonPayload,
}

#[derive(Deserialize, Debug)]
pub enum JsonProtocol {
    TCP,
    UDP,
    ICMP
}

#[derive(Deserialize, Debug)]
#[serde(tag = "type")]
enum JsonPayload {
    Lengths { lengths: Vec<usize> },
    HexCodes { content: Vec<String> },
    Text { content: Vec<String> },
    NoPayload
}

impl JsonPayload {

    fn into_payload_type(self) -> PayloadType {
        match self {
                            JsonPayload::Lengths { lengths: l } => PayloadType::Random(l),
                            JsonPayload::NoPayload => PayloadType::Empty,
                            JsonPayload::HexCodes { content: p } => PayloadType::Replay(p.into_iter().map(|s| hex::decode(s).expect("Payload decoding failed")).collect()),
                            JsonPayload::Text { content: p } => PayloadType::Text(p),
        }
    }
}

impl<T: EdgeType> TimedAutomaton<T> {
    pub fn import_timed_automaton(a: JsonAutomaton, symbol_parser: impl Fn(String, PayloadType) -> T) -> Self {
        let mut nodes_nb = 0;
        let mut graph : Vec<TimedNode<T>> = vec![];
        for _ in 0..a.edges.len()+1 { // the automaton is connected, so #edges+1 >= #nodes
            graph.push(TimedNode { out_edges: vec![] });
        }
        for e in a.edges {
            let data =
                if e.symbol.eq("$") {
                    None
                } else {
                    Some(symbol_parser(e.symbol, e.payloads.into_payload_type()))
                };
            let new_edge = TimedEdge { dst_node: e.dst, src_node: e.src, transition_proba: e.p, data, p: EdgeDistribution::Normal, mu: e.mu.try_into().unwrap(), cov: [[e.cov[0][0], e.cov[0][1]],[e.cov[1][0],e.cov[1][1]]] };
            graph[e.src].out_edges.push(new_edge);
            nodes_nb = nodes_nb.max(e.src+1).max(e.dst+1);
        }
        graph.truncate(nodes_nb);
        // dbg!(&graph);
        TimedAutomaton::<T> { graph, metadata: a.metadata, noise: a.noise, initial_state: a.initial_state, accepting_state: a.accepting_state }
    }
}

