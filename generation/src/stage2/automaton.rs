#![allow(unused)]

use crate::structs::*;
use crate::tcp::*;
use kd_tree::KdTree;
use rand::distributions::WeightedIndex;
use rand::prelude::*;
use rand::Rng;
use rand_distr::{Distribution, Normal, Poisson};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

// Automaton are graphs. Graphs are not straightforward in Rust due to ownership, so we reference nodes by their index in the graph.

#[derive(Debug, Clone)]
struct CrossProductTimedNode<T: EdgeType> {
    in_edges: Vec<TimedEdge<T>>,
    dist: Option<WeightedIndex<u32>>,
    fwd_pkt_count: usize,
    bwd_pkt_count: usize,
}

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
struct TimedEdge<T: EdgeType> {
    // TODO: plutôt que "Option<T>" pour data, utiliser un enum
    // "EpsilonEdge"/"NonEpsilonEdge" pour tout ce qui étiquette une
    // transition (symbole et valeur)
    dst_node: usize,
    data: Option<Arc<T>>,  // no data if transition to sink state
    transition_proba: f32, // not used
    count: u32,
    mu: [f32; 2],
    cov: [[f32; 2]; 2], // TODO: créer directement loi normale / poisson
    p: EdgeDistribution,
}

impl EdgeDistribution {
    // https://en.wikipedia.org/wiki/Multivariate_normal_distribution#Conditional_distributions

    fn sample(&self, rng: &mut impl RngCore, cond_mu: f32, cond_var: f32) -> f32 {
        match &self {
            EdgeDistribution::Normal => {
                let normal = Normal::new(cond_mu, cond_var.sqrt()).unwrap();
                normal.sample(rng).max(0.)
            }
            EdgeDistribution::Poisson => {
                let poisson = Poisson::new((cond_mu + cond_var) / 2.0).unwrap();
                poisson.sample(rng).max(0.)
            }
            EdgeDistribution::Gamma => todo!(),
        }
    }
}

#[derive(Debug)]
pub struct CrossProductTimedAutomaton<T: EdgeType> {
    graph: Vec<CrossProductTimedNode<T>>,
    initial_state: usize,
    accepting_states: KdTree<([i32; 2], usize)>, // to quickly find the closest possible accepting
    // state
    metadata: AutomatonMetaData,
}

impl<T: EdgeType> From<TimedAutomaton<T>> for CrossProductTimedAutomaton<T> {
    fn from(automaton: TimedAutomaton<T>) -> Self {
        const MAX_FLOW_COUNT: usize = 100;

        #[derive(Eq, Hash, PartialEq, Copy, Clone, Debug)]
        struct CrossProductNode {
            state: usize,
            fwd: usize,
            bwd: usize,
        };

        log::trace!(
            "Computing cross-product automata for {}",
            automaton.metadata.automaton_name
        );
        let max_state_count = (MAX_FLOW_COUNT + 1) * automaton.graph.len();
        let mut openset = Vec::with_capacity(max_state_count);
        openset.push(CrossProductNode {
            state: automaton.initial_state,
            fwd: 0,
            bwd: 0,
        });
        let mut predecessors: HashMap<CrossProductNode, Vec<TimedEdge<T>>> =
            HashMap::with_capacity(max_state_count);
        let mut closeset = Vec::with_capacity(max_state_count);
        let mut seen: HashMap<CrossProductNode, ()> = HashMap::with_capacity(max_state_count);
        let mut current_node_index = 0;
        while let Some(node) = openset.pop() {
            if seen.contains_key(&node) {
                continue;
            }
            closeset.push(node);
            seen.insert(node, ());
            for e in automaton.graph[node.state].out_edges.iter() {
                let successor_node = match &e.data {
                    None => CrossProductNode {
                        state: e.dst_node,
                        fwd: node.fwd,
                        bwd: node.bwd,
                    }, // epsilon-transitions do not affect the counts
                    Some(d) if d.get_direction() == PacketDirection::Forward => CrossProductNode {
                        state: e.dst_node,
                        fwd: node.fwd + 1,
                        bwd: node.bwd,
                    },
                    _ => CrossProductNode {
                        state: e.dst_node,
                        fwd: node.fwd,
                        bwd: node.bwd + 1,
                    },
                };
                if successor_node.fwd + successor_node.bwd <= MAX_FLOW_COUNT {
                    openset.push(successor_node);
                    let mut new_edge = e.clone();
                    new_edge.dst_node = current_node_index;
                    let mut value = predecessors.get_mut(&successor_node);
                    if let Some(vec) = value {
                        vec.push(new_edge);
                    } else {
                        predecessors.insert(successor_node, vec![new_edge]);
                    }
                }
            }
            current_node_index += 1;
        }

        log::trace!("Cross-product automaton has {} states", closeset.len());

        // transform it into a CrossProductTimedAutomaton
        let mut graph: Vec<CrossProductTimedNode<T>> = Vec::new();
        let mut accepting_states = Vec::new();
        for (i, node) in closeset.into_iter().enumerate() {
            if node.state == automaton.accepting_state {
                accepting_states.push(([node.fwd as i32, node.bwd as i32], i));
            }
            let in_edges: Option<Vec<TimedEdge<T>>> = predecessors.remove(&node);
            let dist = in_edges
                .as_ref()
                .map(|v| WeightedIndex::new(v.iter().map(|e| e.count)).unwrap());
            let in_edges = in_edges.unwrap_or_default();
            graph.push(CrossProductTimedNode {
                in_edges,
                dist,
                fwd_pkt_count: node.fwd,
                bwd_pkt_count: node.bwd,
            });
        }
        CrossProductTimedAutomaton {
            graph,
            initial_state: 0,
            accepting_states: KdTree::build(accepting_states),
            metadata: automaton.metadata,
        }
    }
}

impl<T: EdgeType> CrossProductTimedAutomaton<T> {
    pub fn is_compatible_with(&self, port: u16) -> bool {
        self.metadata.select_dst_ports.contains(&port)
    }

    pub fn sample<U>(
        &self,
        rng: &mut impl RngCore,
        fd: &FlowData,
        header_creator: impl Fn(Payload, NoiseType, Duration, &T) -> U,
    ) -> Vec<U> {
        let mut output = vec![];
        let mut current_state = self
            .accepting_states
            .nearest(&([fd.fwd_packets_count as i32, fd.bwd_packets_count as i32]))
            .unwrap()
            .item
            .1;
        let mut current_ts = fd.timestamp;
        // TODO: sample with noise
        while current_state != self.initial_state {
            debug_assert!(!self.graph[current_state].in_edges.is_empty());
            let index = match &self.graph[current_state].dist {
                None => 0, // only one outgoing edge
                Some(d) => d.sample(rng),
            };
            let e = &self.graph[current_state].in_edges[index];
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
        output.reverse();
        output
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

// IMPORT FROM JSON
// TODO: rendre ça plus propre avec des "From/Into"

#[derive(Deserialize, Debug)]
pub struct JsonAutomaton {
    edges: Vec<JsonEdge>,
    noise: Noise,
    initial_state: usize,
    accepting_state: usize,
    pub protocol: Protocol,
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
    count: u32,
    payloads: JsonPayload,
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
            graph.push(TimedNode {
                out_edges: vec![],
                dist: None,
            });
        }
        // TODO: transition proba devrait être stocké dans une structure temporaire pour ne pas
        // prendre inutilement de la place dans le modèle
        for e in a.edges {
            let data = if e.symbol.eq("$") {
                None
            } else {
                Some(Arc::new(symbol_parser(e.symbol, e.payloads.into())))
            };
            let new_edge = TimedEdge {
                dst_node: e.dst,
                count: e.count,
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
                s.dist = Some(
                    WeightedIndex::new(s.out_edges.iter().map(|e| e.transition_proba)).unwrap(),
                );
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
