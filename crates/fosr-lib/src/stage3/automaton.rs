use crate::structs::*;
use base64::Engine;
use nalgebra::Vector2;
use rand_core::*;
use rand_distr::weighted::WeightedIndex;
use rand_distr::{Distribution, Normal, Poisson};
use serde::Deserialize;
use statrs::distribution::Continuous;
use statrs::distribution::MultivariateNormal;
use statrs::statistics::{MeanN, VarianceN};
use std::cmp::max;
use std::collections::HashMap;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::sync::Arc;
use std::time::Duration;

// Automaton are graphs. Graphs are not straightforward in Rust due to ownership, so we reference nodes by their index in the graph.

#[derive(Debug, Clone)]
#[allow(unused)]
struct CrossProductTimedNode<T: EdgeType> {
    in_edges: Vec<TimedEdge<T>>,
    dist: Option<WeightedIndex<u32>>,
}

#[derive(Debug, Clone)]
struct TimedNode<T: EdgeType> {
    out_edges: Vec<TimedEdge<T>>,
    dist: Option<WeightedIndex<f32>>,
}

#[derive(Debug, Clone)]
#[allow(unused)]
enum EdgeDistribution {
    Normal, // TODO: add cond_var to compute it only once
    Poisson,
    Gamma, // TODO
}

#[derive(Debug, Clone)]
pub struct TimedEdge<T: EdgeType> {
    // TODO: plutôt que "Option<T>" pour data, utiliser un enum
    // "EpsilonEdge"/"NonEpsilonEdge" pour tout ce qui étiquette une
    // transition (symbole et valeur)
    dst_node: usize,
    data: Option<Arc<T>>,  // no data if transition to sink state
    transition_proba: f32, // not used
    #[allow(unused)]
    count: u32,
    mu: [f32; 2],
    cov: [[f32; 2]; 2], // TODO: créer directement loi normale / poisson
    p: EdgeDistribution,
}

impl EdgeDistribution {
    // https://en.wikipedia.org/wiki/Multivariate_normal_distribution#Conditional_distributions

    fn sample(&self, rng: &mut impl Rng, cond_mu: f32, cond_var: f32) -> f32 {
        match &self {
            EdgeDistribution::Normal => {
                let normal = Normal::new(cond_mu, cond_var.sqrt()).unwrap();
                normal.sample(rng).max(0.001)
            }
            EdgeDistribution::Poisson => {
                let poisson = Poisson::new((cond_mu + cond_var) / 2.0).unwrap();
                poisson.sample(rng).max(0.001)
            }
            EdgeDistribution::Gamma => todo!(),
        }
    }
}

#[derive(Debug)]
#[allow(unused)]
pub struct CrossProductTimedAutomaton<T: EdgeType> {
    graph: Vec<CrossProductTimedNode<T>>,
    initial_state: usize,
    accepting_states_per_cluster: Vec<Vec<usize>>,
    accepting_states_distr_per_cluster: Vec<WeightedIndex<u32>>,
    #[allow(unused)]
    metadata: AutomatonMetaData,
}

impl<T: EdgeType> From<TimedAutomaton<T>> for CrossProductTimedAutomaton<T> {
    fn from(automaton: TimedAutomaton<T>) -> Self {
        let mut max_flow_count: usize = 2;
        for c in automaton.clusters.iter() {
            let fwd = (c.mean().unwrap()[0] + 3f64 * c.variance().unwrap()[0].sqrt()) as usize;
            // dbg!(&c.mean().unwrap());
            // dbg!(&c.variance().unwrap());
            let bwd = (c.mean().unwrap()[1] + 3f64 * c.variance().unwrap()[3].sqrt()) as usize;
            // println!("{fwd} et {bwd}");
            max_flow_count = max(max_flow_count, fwd + bwd);
        }

        let max_fwd_bwd_index: usize = max_flow_count * (max_flow_count + 1) / 2 + max_flow_count;

        #[derive(Eq, Hash, PartialEq, Copy, Clone, Debug)]
        struct CrossProductNode {
            state: usize,
            fwd: usize,
            bwd: usize,
        }

        impl CrossProductNode {
            fn get_index(&self, max_fwd_bwd_index: usize) -> usize {
                // Cantor pairing function: https://en.wikipedia.org/wiki/Pairing_function
                self.state * (max_fwd_bwd_index + 1)
                    + (self.fwd + self.bwd) * (self.fwd + self.bwd + 1) / 2
                    + self.bwd
            }
        }

        log::trace!(
            "Computing cross-product automata for {}",
            automaton.metadata.service
        );
        let max_state_count = (max_fwd_bwd_index + 1) * automaton.graph.len();
        let mut openset = Vec::with_capacity(max_state_count);
        openset.push(CrossProductNode {
            state: automaton.initial_state,
            fwd: 0,
            bwd: 0,
        });
        let mut predecessors: HashMap<CrossProductNode, Vec<TimedEdge<T>>> =
            HashMap::with_capacity(max_state_count);
        let mut closeset = Vec::with_capacity(max_state_count);
        let mut seen: Vec<bool> = Vec::with_capacity(max_state_count);
        seen.resize(max_state_count, false);
        let mut current_node_index = 0;
        // A simple search
        while let Some(node) = openset.pop() {
            let index = node.get_index(max_fwd_bwd_index);
            if seen[index] {
                continue;
            }
            closeset.push(node);
            seen[index] = true;
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
                if successor_node.fwd + successor_node.bwd <= max_flow_count {
                    openset.push(successor_node);
                    let mut new_edge = e.clone();
                    new_edge.dst_node = current_node_index;
                    let value = predecessors.get_mut(&successor_node);
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

        let mut accepting_states_per_cluster: Vec<Vec<usize>> = Vec::new();
        let mut marginal_weights_per_cluster: Vec<Vec<u32>> = Vec::new();
        for _ in automaton.clusters.iter() {
            accepting_states_per_cluster.push(Vec::new());
            marginal_weights_per_cluster.push(Vec::new());
        }

        for (i, node) in closeset.into_iter().enumerate() {
            // if node.state == automaton.accepting_state {
            //     accepting_states.push(([node.fwd as i64, node.bwd as i64], i));
            // }
            let in_edges: Option<Vec<TimedEdge<T>>> = predecessors.remove(&node);
            let dist = in_edges
                .as_ref()
                .map(|v| WeightedIndex::new(v.iter().map(|e| e.count)).unwrap());

            if node.state == automaton.accepting_state {
                let mut max: Option<usize> = None;
                let mut max_value: Option<f64> = None;
                for (j, cluster) in automaton.clusters.iter().enumerate() {
                    let p = cluster.ln_pdf(&Vector2::new(node.fwd as f64, node.bwd as f64));
                    if let Some(val) = max_value 
                    {
                        if val < p {
                            max_value = Some(p);
                            max = Some(j);
                        }
                    } else {
                        max_value = Some(p);
                        max = Some(j);
                    }
                }
                // println!("Most probable cluster for {} and {}: {}", node.fwd, node.bwd, max.unwrap());

                accepting_states_per_cluster[max.unwrap()].push(i);
                marginal_weights_per_cluster[max.unwrap()].push(
                    in_edges
                        .as_ref()
                        .map(|v| v.iter().map(|e| e.count).sum())
                        .unwrap_or(0),
                );
            }

            let in_edges = in_edges.unwrap_or_default();
            graph.push(CrossProductTimedNode { in_edges, dist });
        }
        CrossProductTimedAutomaton {
            accepting_states_per_cluster,
            accepting_states_distr_per_cluster: marginal_weights_per_cluster
                .into_iter()
                .map(|v| WeightedIndex::new(v).expect("No accepting state for a cluster!"))
                .collect(),
            graph,
            initial_state: 0,
            metadata: automaton.metadata,
        }
    }
}

pub trait Automaton<T: EdgeType> {
    fn iat_to_duration(&self, iat: f32) -> Duration;

    fn get_initial_state(&self, rng: &mut impl Rng, packet_cluster: usize) -> usize;

    fn is_final(&self, n: usize) -> bool;

    fn get_next_edge(&self, rng: &mut impl Rng, current_state: usize) -> &TimedEdge<T>;

    fn finalize_timestamps<U: PacketInfo>(&self, vector: &mut Vec<U>, ts: Duration);
}

impl<T: EdgeType> Automaton<T> for CrossProductTimedAutomaton<T> {
    fn iat_to_duration(&self, iat: f32) -> Duration {
        Duration::from_nanos((iat * 1e3) as u64)
    }

    fn is_final(&self, n: usize) -> bool {
        n == self.initial_state
    }

    fn finalize_timestamps<U: PacketInfo>(&self, vector: &mut Vec<U>, ts: Duration) {
        vector.reverse();
        let mut current_ts = ts;
        for p in vector.iter_mut() {
            current_ts += p.get_ts();
            p.set_ts(current_ts);
        }
    }

    fn get_initial_state(&self, rng: &mut impl Rng, packet_cluster: usize) -> usize {
        self.accepting_states_per_cluster[packet_cluster]
            [self.accepting_states_distr_per_cluster[packet_cluster].sample(rng)]
    }

    fn get_next_edge(&self, rng: &mut impl Rng, current_state: usize) -> &TimedEdge<T> {
        debug_assert!(!self.graph[current_state].in_edges.is_empty());
        let index = match &self.graph[current_state].dist {
            None => 0, // only one outgoing edge
            Some(d) => d.sample(rng),
        };
        &self.graph[current_state].in_edges[index]
    }
}

impl<T: EdgeType> Automaton<T> for TimedAutomaton<T> {
    fn iat_to_duration(&self, iat: f32) -> Duration {
        Duration::from_nanos((iat * 1e3) as u64)
    }

    fn is_final(&self, n: usize) -> bool {
        n == self.accepting_state
    }

    fn finalize_timestamps<U: PacketInfo>(&self, vector: &mut Vec<U>, ts: Duration) {
        let mut current_ts = ts;
        for p in vector.iter_mut() {
            current_ts += p.get_ts();
            p.set_ts(current_ts);
        }
    }

    fn get_initial_state(&self, _rng: &mut impl Rng, _packet_cluster: usize) -> usize {
        self.initial_state
    }

    fn get_next_edge(&self, rng: &mut impl Rng, current_state: usize) -> &TimedEdge<T> {
        debug_assert!(!self.graph[current_state].out_edges.is_empty());
        let index = match &self.graph[current_state].dist {
            None => 0, // only one outgoing edge
            Some(d) => d.sample(rng),
        };
        &self.graph[current_state].out_edges[index]
    }
}

pub fn sample<T: EdgeType, U: PacketInfo>(
    rng: &mut impl Rng,
    automaton: &impl Automaton<T>,
    fd: &FlowData,
    header_creator: impl Fn(Payload, NoiseType, Duration, &T) -> U,
) -> Vec<U> {
    let mut output = Vec::new();
    let mut current_state = automaton.get_initial_state(rng, fd.packets_count_cluster);

    while !automaton.is_final(current_state) {
        let e = automaton.get_next_edge(rng, current_state);
        if let Some(data) = &e.data {
            // if $-transition, don’t create a header
            let (payload, payload_size) = match data.get_payload_type() {
                PayloadType::Empty => (Payload::Empty, 0),
                PayloadType::Random(sizes, distrib) => {
                    let size = sizes[distrib.sample(rng)];
                    (Payload::Random(size), size)
                }
                PayloadType::Text(tss, distrib) => {
                    let ts = &tss[distrib.sample(rng)];
                    (Payload::Binary(ts), ts.len())
                }
                PayloadType::Binary(tss, distrib) => {
                    let ts = &tss[distrib.sample(rng)];
                    (Payload::Binary(ts), ts.len())
                }
            };
            let cond_mu = e.mu[0] + e.cov[0][1] / e.cov[1][1] * (payload_size as f32 - e.mu[1]);
            let cond_var = (0.001_f32).max(e.cov[0][0] - e.cov[0][1] * e.cov[0][1] / e.cov[1][1]);
            let iat = e.p.sample(rng, cond_mu, cond_var);
            let data = header_creator(
                payload,
                NoiseType::None,
                automaton.iat_to_duration(iat),
                data,
            );
            output.push(data);
        }
        current_state = e.dst_node;
    }
    automaton.finalize_timestamps(&mut output, fd.timestamp);
    output
}

#[derive(Debug, Clone)]
pub struct TimedAutomaton<T: EdgeType> {
    graph: Vec<TimedNode<T>>,
    metadata: AutomatonMetaData,
    clusters: Vec<MultivariateNormal<nalgebra::Const<2>>>,
    initial_state: usize,
    accepting_state: usize,
}

impl<T: EdgeType> Display for TimedAutomaton<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self.metadata.conn_state {
            Some(s) => write!(
                f,
                "automaton {:?} for state {s:?} learned from {} on {}",
                self.metadata.service, self.metadata.input_file, self.metadata.creation_time
            ),
            None => write!(
                f,
                "automaton {:?} learned from {} on {}",
                self.metadata.service, self.metadata.input_file, self.metadata.creation_time
            ),
        }
    }
}

#[derive(Deserialize, Debug, Clone)]
#[allow(unused)]
pub struct JsonAutomatonMetaData {
    pub service: String,
    pub conn_state: String,
    pub input_file: String,
    pub creation_time: String,
}

#[derive(Deserialize, Debug, Clone)]
#[allow(unused)]
#[serde(try_from = "JsonAutomatonMetaData")]
pub struct AutomatonMetaData {
    pub service: String,
    pub conn_state: Option<TCPConnState>,
    pub input_file: String,
    pub creation_time: String,
}

impl TryFrom<JsonAutomatonMetaData> for AutomatonMetaData {
    type Error = String;

    fn try_from(m: JsonAutomatonMetaData) -> Result<Self, String> {
        let conn_state = match m.conn_state.as_str() {
            "SF" => Some(TCPConnState::SF),
            "SH" => Some(TCPConnState::SH),
            "RST" => Some(TCPConnState::RST),
            "S0" => Some(TCPConnState::S0),
            "REJ" => Some(TCPConnState::REJ),
            "none" => None,
            s => Err(format!("Unknown connection state: {s}"))?,
        };
        Ok(AutomatonMetaData {
            service: m.service,
            conn_state,
            input_file: m.input_file,
            creation_time: m.creation_time,
        })
    }
}

#[derive(Deserialize, Debug, Clone)]
#[allow(unused)]
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
    #[allow(unused)]
    noise: Noise,
    initial_state: usize,
    accepting_state: usize,
    pub protocol: L4Proto,
    pub metadata: AutomatonMetaData,
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
    Lengths {
        weights: Option<Vec<u64>>,
        lengths: Vec<usize>,
    },
    HexCodes {
        weights: Option<Vec<u64>>,
        content: Vec<String>,
    },
    Base64 {
        weights: Option<Vec<u64>>,
        content: Vec<String>,
    },
    Text {
        weights: Option<Vec<u64>>,
        content: Vec<String>,
    },
    NoPayload,
}

impl TryFrom<JsonPayload> for PayloadType {
    type Error = String;

    fn try_from(p: JsonPayload) -> Result<Self, String> {
        let hex_decode = |s: String| {
            s.as_bytes()
                .chunks(2)
                .map(|pair| {
                    ((pair[0] as char).to_digit(16).unwrap() * 16
                        + (pair[1] as char).to_digit(16).unwrap()) as u8
                })
                .collect()
        };

        match p {
            JsonPayload::Lengths {
                weights: w,
                lengths: l,
            } => {
                if l.is_empty() {
                    Err("No payload information".to_string())
                } else {
                    let weights = w.unwrap_or_else(|| vec![1; l.len()]);
                    Ok(PayloadType::Random(
                        l,
                        WeightedIndex::new(weights).map_err(|e| format!("Weights error: {e}"))?,
                    ))
                }
            }
            JsonPayload::NoPayload => Ok(PayloadType::Empty),
            JsonPayload::HexCodes {
                weights: w,
                content: p,
            } => {
                if p.is_empty() {
                    Err("No payload information".to_string())
                } else {
                    let weights = w.unwrap_or_else(|| vec![1; p.len()]);
                    Ok(PayloadType::Binary(
                        Box::leak(Box::new(p.into_iter().map(hex_decode).collect())),
                        WeightedIndex::new(weights).map_err(|e| format!("Weights error: {e}"))?,
                    ))
                }
            }
            JsonPayload::Base64 {
                weights: w,
                content: p,
            } => {
                if p.is_empty() {
                    Err("No payload information".to_string())
                } else {
                    let weights = w.unwrap_or_else(|| vec![1; p.len()]);
                    Ok(PayloadType::Binary(
                        Box::leak(Box::new(
                            p.into_iter()
                                .map(|s| base64::prelude::BASE64_STANDARD.decode(s).unwrap())
                                .collect(),
                        )),
                        WeightedIndex::new(weights).map_err(|e| format!("Weights error: {e}"))?,
                    ))
                }
            }
            JsonPayload::Text {
                weights: w,
                content: p,
            } => {
                if p.is_empty() {
                    Err("No payload information".to_string())
                } else {
                    let weights = w.unwrap_or_else(|| vec![1; p.len()]);
                    Ok(PayloadType::Text(
                        Box::leak(Box::new(p.into_iter().map(|v| v.into()).collect())),
                        WeightedIndex::new(weights).map_err(|e| format!("Weights error: {e}"))?,
                    ))
                }
            }
        }
    }
}

impl<T: EdgeType> TimedAutomaton<T> {
    pub fn import_timed_automaton(
        a: JsonAutomaton,
        clusters: Vec<MultivariateNormal<nalgebra::Const<2>>>,
        symbol_parser: impl Fn(String, PayloadType) -> T,
    ) -> Result<Self, String> {
        let mut nodes_nb = 0;
        let mut graph: Vec<TimedNode<T>> = vec![];
        for _ in 0..a.edges.len() + 1 {
            // the automaton is connected, so #edges+1 >= #nodes
            graph.push(TimedNode {
                out_edges: vec![],
                dist: None,
            });
        }
        for e in a.edges {
            let data = if e.symbol.eq("$") {
                None
            } else {
                Some(Arc::new(symbol_parser(e.symbol, e.payloads.try_into()?)))
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
        Ok(TimedAutomaton::<T> {
            clusters,
            graph,
            metadata: a.metadata,
            initial_state: a.initial_state,
            accepting_state: a.accepting_state,
        })
    }
}
