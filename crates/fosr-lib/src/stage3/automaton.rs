use crate::structs::*;
use base64::Engine;
use nalgebra::Vector2;
use rand_core::*;
use rand_distr::weighted::WeightedIndex;
use rand_distr::{Distribution, Gamma};
use serde::Deserialize;
use statrs::distribution::Continuous;
use statrs::distribution::MultivariateNormal;
use statrs::statistics::{MeanN, VarianceN};
use std::cmp::max;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::sync::Arc;
use std::time::Duration;

// Automaton are graphs. Graphs are not straightforward in Rust due to ownership, so we reference nodes by their index in the graph.

#[derive(Debug, Clone)]
#[allow(unused)]
struct CrossProductTimedNode<T: EdgeType> {
    in_edges: Vec<CrossProductTimedEdge<T>>,
    dist: Option<Arc<WeightedIndex<u32>>>,
}

#[derive(Debug, Clone)]
struct TimedNode<T: EdgeType> {
    out_edges: Vec<TimedEdge<T>>,
    dist: Option<WeightedIndex<f32>>,
}

#[derive(Deserialize, Debug)]
#[serde(tag = "law")]
#[serde(rename_all = "lowercase")]
enum JsonEdgeDistribution {
    Constant { value: f32 },
    Gamma { shape: f32, loc: f32, scale: f32 },
}

#[derive(Deserialize, Debug, Clone)]
#[serde(from = "JsonEdgeDistribution")]
enum EdgeDistribution {
    Constant(f32),
    Gamma { p: Gamma<f32>, loc: f32 },
}

impl EdgeDistribution {
    fn sample_iat(&self, rng: &mut impl Rng) -> f32 {
        match self {
            EdgeDistribution::Constant(val) => *val,
            EdgeDistribution::Gamma { p, loc } => p.sample(rng) + loc,
        }
    }
}

impl From<JsonEdgeDistribution> for EdgeDistribution {
    fn from(d: JsonEdgeDistribution) -> Self {
        match d {
            JsonEdgeDistribution::Constant { value } => EdgeDistribution::Constant(value),
            JsonEdgeDistribution::Gamma { shape, loc, scale } => EdgeDistribution::Gamma {
                p: Gamma::new(shape, scale).expect("Cannot create Gamma distribution"),
                loc,
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct CrossProductTimedEdge<T: EdgeType> {
    // to reduce the memory footprint, we only keep the essentials
    dst_node: u32,
    data: Option<Arc<T>>, // no data if transition to sink state
    iat_distr: Arc<EdgeDistribution>,
}

#[derive(Debug, Clone)]
pub struct TimedEdge<T: EdgeType> {
    // TODO: plutôt que "Option<T>" pour data, utiliser un enum
    // "EpsilonEdge"/"NonEpsilonEdge" pour tout ce qui étiquette une
    // transition (symbole et valeur)
    dst_node: u32,
    data: Option<Arc<T>>, // no data if transition to sink state
    transition_proba: f32,
    count: u32,
    iat_distr: Arc<EdgeDistribution>,
}

#[derive(Debug)]
#[allow(unused)]
pub struct CrossProductTimedAutomaton<T: EdgeType> {
    graph: Vec<CrossProductTimedNode<T>>,
    initial_state: u32,
    accepting_states_per_cluster: Vec<Vec<u32>>,
    accepting_states_distr_per_cluster: Vec<WeightedIndex<u32>>,
    #[allow(unused)]
    metadata: AutomatonMetaData,
}

impl<T: EdgeType> From<TimedAutomaton<T>> for CrossProductTimedAutomaton<T> {
    fn from(automaton: TimedAutomaton<T>) -> Self {
        let mut max_fwd: u32 = 1;
        let mut max_bwd: u32 = 1;
        for c in automaton.clusters.iter() {
            let fwd = (c.mean().unwrap()[0] + 3f64 * c.variance().unwrap()[0].sqrt()) as u32;
            // dbg!(&c.mean().unwrap());
            // dbg!(&c.variance().unwrap());
            let bwd = (c.mean().unwrap()[1] + 3f64 * c.variance().unwrap()[3].sqrt()) as u32;
            // println!("{fwd} et {bwd}");
            max_fwd = max(max_fwd, fwd);
            max_bwd = max(max_bwd, bwd);
        }

        max_fwd = 200;
        max_bwd = 200;

        // println!(
        //     "max: {max_fwd} et {max_bwd}, graph: {}",
        //     automaton.graph.len()
        // );
        let max_flow_count: u32 = max_fwd + max_bwd;
        #[derive(Eq, Hash, PartialEq, Copy, Clone, Debug)]
        struct CrossProductNode {
            state: u32,
            fwd: u32,
            bwd: u32,
        }

        log::trace!(
            "Computing cross-product automata for {}",
            automaton.metadata.service
        );
        let mut openset = Vec::with_capacity(max_flow_count as usize);
        openset.push(CrossProductNode {
            state: automaton.initial_state,
            fwd: 0,
            bwd: 0,
        });
        let mut predecessors: HashMap<CrossProductNode, Vec<TimedEdge<T>>> =
            HashMap::with_capacity(max_flow_count as usize);
        let mut closeset = Vec::with_capacity(max_flow_count as usize);
        let mut seen = HashSet::new();
        let mut current_node_index = 0;
        // A simple search
        while let Some(node) = openset.pop() {
            if seen.contains(&node) {
                continue;
            }
            closeset.push(node);
            for e in automaton.graph[node.state as usize].out_edges.iter() {
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
                if successor_node.fwd <= max_fwd && successor_node.bwd <= max_bwd {
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
            seen.insert(node);
            current_node_index += 1;
        }

        log::trace!("Cross-product automaton has {} states", closeset.len());

        // transform it into a CrossProductTimedAutomaton
        let mut graph: Vec<CrossProductTimedNode<T>> = Vec::new();

        let mut accepting_states_per_cluster: Vec<Vec<u32>> = Vec::new();
        let mut marginal_weights_per_cluster: Vec<Vec<u32>> = Vec::new();
        for _ in automaton.clusters.iter() {
            accepting_states_per_cluster.push(Vec::new());
            marginal_weights_per_cluster.push(Vec::new());
        }

        let mut weighted_indices: HashMap<Vec<u32>, Arc<WeightedIndex<u32>>> = HashMap::new();

        for (i, node) in closeset.into_iter().enumerate() {
            let in_edges: Option<Vec<TimedEdge<T>>> = predecessors.remove(&node);
            let dist = in_edges.as_ref().map(|v| {
                let vec: Vec<u32> = v.iter().map(|e| e.count).collect();
                if let Some(wi) = weighted_indices.get(&vec) {
                    wi.clone()
                } else {
                    let wi = Arc::new(WeightedIndex::new(vec.clone()).unwrap());
                    weighted_indices.insert(vec, wi.clone());
                    wi
                }
            });
            if node.state == automaton.accepting_state {
                let mut max: Option<u32> = None;
                let mut max_value: Option<f64> = None;
                for (j, cluster) in automaton.clusters.iter().enumerate() {
                    let p = cluster.ln_pdf(&Vector2::new(node.fwd as f64, node.bwd as f64));
                    if let Some(val) = max_value {
                        if val < p {
                            max_value = Some(p);
                            max = Some(j as u32);
                        }
                    } else {
                        max_value = Some(p);
                        max = Some(j as u32);
                    }
                }
                // println!("Most probable cluster for {} and {}: {}", node.fwd, node.bwd, max.unwrap());

                accepting_states_per_cluster[max.unwrap() as usize].push(i as u32);
                marginal_weights_per_cluster[max.unwrap() as usize].push(
                    in_edges
                        .as_ref()
                        .map(|v| v.iter().map(|e| e.count).sum())
                        .unwrap_or(0),
                );
            }

            let in_edges: Vec<CrossProductTimedEdge<T>> = in_edges
                .unwrap_or_default()
                .into_iter()
                .map(|e| CrossProductTimedEdge {
                    dst_node: e.dst_node,
                    data: e.data,
                    iat_distr: e.iat_distr,
                })
                .collect();
            graph.push(CrossProductTimedNode { in_edges, dist });
        }

        // dbg!(std::mem::size_of_val(&*graph));
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

    fn get_initial_state(&self, rng: &mut impl Rng, packet_cluster: usize) -> u32;

    fn is_final(&self, n: u32) -> bool;

    fn get_next_edge(&self, rng: &mut impl Rng, current_state: u32) -> &CrossProductTimedEdge<T>;

    fn finalize_timestamps<U: PacketInfo>(&self, vector: &mut Vec<U>, ts: Duration);
}

impl<T: EdgeType> Automaton<T> for CrossProductTimedAutomaton<T> {
    fn iat_to_duration(&self, iat: f32) -> Duration {
        Duration::from_nanos((iat * 1e3) as u64)
    }

    fn is_final(&self, n: u32) -> bool {
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

    fn get_initial_state(&self, rng: &mut impl Rng, packet_cluster: usize) -> u32 {
        self.accepting_states_per_cluster[packet_cluster]
            [self.accepting_states_distr_per_cluster[packet_cluster].sample(rng)]
    }

    fn get_next_edge(&self, rng: &mut impl Rng, current_state: u32) -> &CrossProductTimedEdge<T> {
        debug_assert!(!self.graph[current_state as usize].in_edges.is_empty());
        let index = match &self.graph[current_state as usize].dist {
            None => 0, // only one outgoing edge
            Some(d) => d.sample(rng),
        };
        &self.graph[current_state as usize].in_edges[index as usize]
    }
}

// impl<T: EdgeType> Automaton<T> for TimedAutomaton<T> {
//     fn iat_to_duration(&self, iat: f32) -> Duration {
//         Duration::from_nanos((iat * 1e3) as u64)
//     }

//     fn is_final(&self, n: u32) -> bool {
//         n == self.accepting_state
//     }

//     fn finalize_timestamps<U: PacketInfo>(&self, vector: &mut Vec<U>, ts: Duration) {
//         let mut current_ts = ts;
//         for p in vector.iter_mut() {
//             current_ts += p.get_ts();
//             p.set_ts(current_ts);
//         }
//     }

//     fn get_initial_state(&self, _rng: &mut impl Rng, _packet_cluster: usize) -> u32 {
//         self.initial_state
//     }

//     fn get_next_edge(&self, rng: &mut impl Rng, current_state: u32) -> &CrossProductTimedEdge<T> {
//         debug_assert!(!self.graph[current_state as usize].out_edges.is_empty());
//         let index = match &self.graph[current_state as usize].dist {
//             None => 0, // only one outgoing edge
//             Some(d) => d.sample(rng),
//         };
//         let e = &self.graph[current_state as usize].out_edges[index as usize];
//         &CrossProductTimedEdge { dst_node: e.dst_node, data: e.data.clone(), iat_distr: e.iat_distr.clone() }
//     }
// }

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
            let (payload, _) = match data.get_payload_type() {
                PayloadType::Empty => (Payload::Empty, 0),
                PayloadType::Binary(tss, distrib) => {
                    let ts = &tss[distrib.sample(rng)];
                    (Payload::Binary(ts), ts.len())
                }
            };
            let iat = e.iat_distr.sample_iat(rng);
            // let cond_mu = e.mu[0] + e.cov[0][1] / e.cov[1][1] * (payload_size as f32 - e.mu[1]);
            // let cond_var = (0.001_f32).max(e.cov[0][0] - e.cov[0][1] * e.cov[0][1] / e.cov[1][1]);
            // let iat = e.p.sample(rng, cond_mu, cond_var);
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
    initial_state: u32,
    accepting_state: u32,
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
    no_noise: f32,
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
    statistics: Noise,
    initial_state: u32,
    accepting_state: u32,
    pub protocol: L4Proto,
    pub metadata: AutomatonMetaData,
}

#[derive(Deserialize, Debug)]
struct JsonEdge {
    p: f32,
    src: u32,
    dst: u32,
    symbol: String,
    iat_distr: EdgeDistribution,
    // mu: Vec<f32>,
    // cov: Vec<Vec<f32>>,
    count: u32,
    payloads: Option<JsonPayload>,
}

#[derive(Deserialize, Debug)]
// #[serde(tag = "type")]
#[serde(into = "PayloadType")]
struct JsonPayload {
    weights: Option<Vec<u64>>,
    content: Vec<String>,
}

// enum JsonPayload {
//     Lengths {
//         weights: Option<Vec<u64>>,
//         lengths: Vec<usize>,
//     },
//     HexCodes {
//         weights: Option<Vec<u64>>,
//         content: Vec<String>,
//     },
//     Base64 {
//         weights: Option<Vec<u64>>,
//         content: Vec<String>,
//     },
//     Text {
//         weights: Option<Vec<u64>>,
//         content: Vec<String>,
//     },
//     NoPayload,
// }

impl TryFrom<JsonPayload> for PayloadType {
    type Error = String;

    fn try_from(p: JsonPayload) -> Result<Self, String> {
        if p.content.is_empty() {
            Ok(PayloadType::Empty)
        } else {
            let weights = p.weights.unwrap_or_else(|| vec![1; p.content.len()]);
            Ok(PayloadType::Binary(
                Box::leak(Box::new(
                    p.content
                        .into_iter()
                        .map(|s| base64::prelude::BASE64_STANDARD.decode(s).unwrap())
                        .collect(),
                )),
                WeightedIndex::new(weights).map_err(|e| format!("Weights error: {e}"))?,
            ))
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
                Some(Arc::new(symbol_parser(
                    e.symbol,
                    e.payloads
                        .unwrap_or(JsonPayload {
                            weights: None,
                            content: vec![],
                        })
                        .try_into()?,
                )))
            };
            let new_edge = TimedEdge {
                dst_node: e.dst,
                count: e.count,
                transition_proba: e.p,
                data,
                iat_distr: Arc::new(e.iat_distr),
            };
            graph[e.src as usize].out_edges.push(new_edge);
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
        graph.truncate(nodes_nb as usize);
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
