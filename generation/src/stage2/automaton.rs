#![allow(unused)]

use crate::structs::*;
use crate::tcp::*;
use rand::distributions::WeightedIndex;
use rand::prelude::*;
use rand::Rng;
use rand_distr::{Distribution, Normal, Poisson};
use serde::Deserialize;
use std::time::Duration;

// Automaton are graphs. Graphs are not straightforward in Rust due to ownership, so we reference nodes by their index in the graph.

#[derive(Debug, Clone)]
struct TimedNode<T: EdgeType> {
    out_edges: Vec<TimedEdge<T>>,
    dist: Option<WeightedIndex<f32>>,
}

#[derive(Debug, Clone)]
enum EdgeDistribution {
    Normal, // TODO: add cond_var to compute it only once
    Poisson,
    Gamma, // TODO
}

#[derive(Debug, Clone)]
struct TimedEdge<T: EdgeType> { // TODO: plutôt que "Option<T>" pour data, utiliser un enum
                                // "EpsilonEdge"/"NonEpsilonEdge" pour tout ce qui étiquette une
                                // transition (symbole et valeur)
    dst_node: usize,
    src_node: usize, // not sure if useful
    data: Option<T>, // no data if transition to sink state
    transition_proba: f32, // not used
    mu: [f32; 2],
    cov: [[f32; 2]; 2], // TODO: créer directement loi normale / poisson 
    p: EdgeDistribution,
}

impl EdgeDistribution {
    // https://en.wikipedia.org/wiki/Multivariate_normal_distribution#Conditional_distributions

    fn sample<R: Rng + ?Sized>(&self, rng: &mut R, cond_mu: f32, cond_var: f32) -> f32 {
        match &self {
            EdgeDistribution::Normal => {
                let normal = Normal::new(cond_mu, cond_var.sqrt()).unwrap();
                normal.sample(rng).max(0.)
            }
            EdgeDistribution::Poisson => {
                let poisson = Poisson::new((cond_mu + cond_var) / 2.0).unwrap();
                poisson.sample(rng).max(0.)
            }
            EdgeDistribution::Gamma => todo!()
        }
    }
}

#[derive(Debug, Clone)]
pub struct TimedAutomaton<T: EdgeType> {
    graph: Vec<TimedNode<T>>,
    metadata: AutomatonMetaData,
    noise: Noise,
    initial_state: usize,
    accepting_state: usize,
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

    pub fn sample<R: Rng + ?Sized, U>(
        &self,
        rng: &mut R,
        initial_ts: Duration,
        header_creator: impl Fn(Payload, NoiseType, Duration, &T) -> U,
    ) -> Vec<U> {
        let mut output = vec![];
        let mut current_state = self.initial_state;
        let mut current_ts = initial_ts;
        // TODO: sample with noise
        while current_state != self.accepting_state {
            assert!(!self.graph[current_state].out_edges.is_empty());
            let index = match &self.graph[current_state].dist {
                None => 0, // only one outgoing edge
                Some(d) => d.sample(rng)
            };
            let e = &self.graph[current_state].out_edges[index];
            if let Some(data) = &e.data {
                // if $-transition, don’t create a header
                let (payload, payload_size) = match data.get_payload_type() {
                    PayloadType::Empty => (Payload::Empty, 0),
                    PayloadType::Random(sizes) => {
                        let size = *sizes.choose(rng).unwrap();
                        (Payload::Random(size), size)
                    }
                    PayloadType::Text(tss) => {
                        // TODO
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
// TODO: rendre ça plus propre avec des "From/Into"

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
    ICMP,
}

#[derive(Deserialize, Debug)]
#[serde(tag = "type")]
#[serde(into = "PayloadType")]
enum JsonPayload {
    Lengths { lengths: Vec<usize> },
    HexCodes { content: Vec<String> },
    Text { content: Vec<String> },
    NoPayload,
}

impl From<JsonPayload> for PayloadType {
    fn from(p: JsonPayload) -> Self {
        match p {
            JsonPayload::Lengths { lengths: l } => PayloadType::Random(l),
            JsonPayload::NoPayload => PayloadType::Empty,
            JsonPayload::HexCodes { content: p } => PayloadType::Replay(
                p.into_iter()
                    .map(|s| hex::decode(s).expect("Payload decoding failed"))
                    .collect(),
            ),
            JsonPayload::Text { content: p } => PayloadType::Text(p),
        }
    }
}

impl<T: EdgeType> TimedAutomaton<T> {
    pub fn import_timed_automaton(
        a: JsonAutomaton,
        symbol_parser: impl Fn(String, PayloadType) -> T,
    ) -> Self {
        let mut nodes_nb = 0;
        let mut graph: Vec<TimedNode<T>> = vec![];
        for _ in 0..a.edges.len() + 1 {
            // the automaton is connected, so #edges+1 >= #nodes
            graph.push(TimedNode { out_edges: vec![], dist: None });
        }
        for e in a.edges {
            let data = if e.symbol.eq("$") {
                None
            } else {
                Some(symbol_parser(e.symbol, e.payloads.into()))
            };
            let new_edge = TimedEdge {
                dst_node: e.dst,
                src_node: e.src,
                transition_proba: e.p,
                data,
                p: EdgeDistribution::Normal,
                mu: e.mu.try_into().unwrap(),
                cov: [[e.cov[0][0], e.cov[0][1]], [e.cov[1][0], e.cov[1][1]]],
            };
            graph[e.src].out_edges.push(new_edge);
            nodes_nb = nodes_nb.max(e.src + 1).max(e.dst + 1);
        }
        for s in graph.iter_mut() {
            if s.out_edges.len() > 1 {
                let mut weights = vec![];
                for e in s.out_edges.iter() {
                    weights.push(e.transition_proba);
                }
                s.dist = Some(WeightedIndex::new(&weights).unwrap());
            }
        }
        // println!("{:?} {:?}",weights, self.graph[current_state].out_edges);
        graph.truncate(nodes_nb);
        // dbg!(&graph);
        TimedAutomaton::<T> {
            graph,
            metadata: a.metadata,
            noise: a.noise,
            initial_state: a.initial_state,
            accepting_state: a.accepting_state,
        }
    }
}
