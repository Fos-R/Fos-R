use crate::models;
use crate::stage3::{
    EdgeType, Flow, FlowData, IcmpPacketInfo, L4Proto, L7Proto, PacketDirection, PacketInfo,
    PacketsIR, SeededData, Stage3, TcpConnState, TcpEdgeTuple, TcpPacketInfo, UdpEdgeTuple,
    UdpPacketInfo, automaton, create_tcp_header, create_udp_header, parse_tcp_symbol,
    parse_udp_symbol,
};

// use indicatif::{ProgressBar, ProgressStyle};
use nalgebra::{matrix, vector};
use rand::prelude::IndexedRandom;
use rand_core::{Rng, SeedableRng};
use rand_pcg::Pcg32;
use serde::Deserialize;
use statrs::distribution::MultivariateNormal;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

#[cfg(not(target_arch = "wasm32"))]
use rayon::prelude::*;

#[derive(Clone)]
struct AutomataSet<T: EdgeType> {
    cons_a: automaton::CrossProductTimedAutomaton<T>,
    uncons_a: automaton::TimedAutomaton<T>,
}

#[derive(Clone)]
pub struct AutomataLibrary {
    tcp_automata: HashMap<(L7Proto, TcpConnState), Vec<AutomataSet<TcpEdgeTuple>>>,
    udp_automata: HashMap<L7Proto, Vec<AutomataSet<UdpEdgeTuple>>>,
}

enum LoadedAutomata {
    TcpAutomata(L7Proto, TcpConnState, AutomataSet<TcpEdgeTuple>),
    UdpAutomata(L7Proto, AutomataSet<UdpEdgeTuple>),
}

fn import_from_str(string: &str, clusters: &[PacketDistr]) -> Result<LoadedAutomata, String> {
    let string = string.to_string();
    let a: automaton::JsonAutomaton =
        serde_json::from_str::<automaton::JsonAutomaton>(string.leak())
            .map_err(|e| format!("Import error: {e}"))?;
    let l7proto = L7Proto::from_str(&a.metadata.service)?;
    let conn_state = a.metadata.conn_state;
    match a.protocol {
        L4Proto::Tcp => {
            assert!(conn_state.is_some());
            let automata_clusters = clusters
                .iter()
                .find_map(|p| {
                    if let PacketDistr::Tcp {
                        conn_state,
                        service,
                        distr,
                    } = p
                        && *service == l7proto
                        && *conn_state == a.metadata.conn_state.unwrap()
                    {
                        Some(distr)
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| {
                    panic!(
                        "No cluster found for {l7proto} and {:?}",
                        conn_state.unwrap()
                    )
                });
            assert!(!automata_clusters.is_empty());
            let a = automaton::TimedAutomaton::<TcpEdgeTuple>::import_timed_automaton(
                a,
                automata_clusters.clone(),
                parse_tcp_symbol,
            )?;
            log::debug!("Import TCP {a}, registered for {l7proto:?}");
            Ok(LoadedAutomata::TcpAutomata(
                l7proto,
                conn_state.unwrap(),
                AutomataSet {
                    uncons_a: a.clone(),
                    cons_a: a.into(),
                },
            ))
        }
        L4Proto::Udp => {
            let automata_clusters = clusters
                .iter()
                .find_map(|p| {
                    if let PacketDistr::Udp { service, distr } = p
                        && *service == l7proto
                    {
                        Some(distr)
                    } else {
                        None
                    }
                })
                .expect("No cluster found for {l7proto}");

            assert!(!automata_clusters.is_empty());
            let a = automaton::TimedAutomaton::<UdpEdgeTuple>::import_timed_automaton(
                a,
                automata_clusters.clone(),
                parse_udp_symbol,
            )?;
            log::debug!("Import UDP {a}, registered for {l7proto:?}");
            Ok(LoadedAutomata::UdpAutomata(
                l7proto,
                AutomataSet {
                    uncons_a: a.clone(),
                    cons_a: a.into(),
                },
            ))
        }
        L4Proto::Icmp => todo!(),
    }
}

impl AutomataLibrary {
    pub fn from_source(models: &models::ModelsSource) -> Result<Self, String> {
        let strings = models
            .get_automata()
            .map_err(|e| format!("Cannot open the automata files: {e}"))?;

        let clusters_string: String = models
            .get_pkt_count_clusters()
            .map_err(|e| format!("Cannot find the clusters: {e}"))?;
        let clusters: Vec<PacketDistr> =
            serde_json::from_str(&clusters_string).expect("Cannot parse the clusters");

        let mut nb = 0;
        let mut lib = AutomataLibrary {
            tcp_automata: HashMap::new(),
            udp_automata: HashMap::new(),
            // icmp_automata: HashMap::new(),
        };

        // load the automata in parallel with rayon

        #[cfg(target_arch = "wasm32")]
        // do not use rayon for wasm32
        let loaded_automata: Vec<Result<LoadedAutomata, String>> = strings
            .iter()
            .map(|s| import_from_str(&s, &clusters))
            .collect();

        #[cfg(not(target_arch = "wasm32"))]
        let loaded_automata: Vec<Result<LoadedAutomata, String>> = strings
            .par_iter()
            .map(|s| import_from_str(s, &clusters))
            .collect();

        for result_automata in loaded_automata {
            match result_automata {
                Ok(LoadedAutomata::TcpAutomata(l7proto, conn_state, a)) => {
                    nb += 1;
                    let v = lib.tcp_automata.entry((l7proto, conn_state)).or_default();
                    v.push(a);
                }
                Ok(LoadedAutomata::UdpAutomata(l7proto, a)) => {
                    nb += 1;
                    let v = lib.udp_automata.entry(l7proto).or_default();
                    v.push(a);
                }
                Err(s) => log::error!("Could not load automaton ({s})"),
            }
        }

        log::info!("{nb} automata have been loaded");
        Ok(lib)
    }
}

#[derive(Deserialize, Debug)]
#[serde(from = "PacketDistrJson")]
pub enum PacketDistr {
    Tcp {
        conn_state: TcpConnState,
        service: L7Proto,
        distr: Vec<MultivariateNormal<nalgebra::Const<2>>>,
    },
    Udp {
        service: L7Proto,
        distr: Vec<MultivariateNormal<nalgebra::Const<2>>>,
    },
}

// Create the multivariate normal distribution on deserialization
impl From<PacketDistrJson> for PacketDistr {
    fn from(d: PacketDistrJson) -> Self {
        match d {
            PacketDistrJson::Tcp {
                conn_state,
                service,
                mu,
                cov,
            } => PacketDistr::Tcp {
                conn_state,
                service: L7Proto::from_str(&service).unwrap(),
                distr: mu
                    .into_iter()
                    .zip(cov)
                    .map(|(m, c)| {
                        // Sometimes the covariance from sklearn’s GaussianMixture is not
                        // symmetric!
                        let c: Vec<f64> = c.into_iter().flatten().collect();
                        let mean = f64::midpoint(c[1], c[2]);
                        MultivariateNormal::new_from_nalgebra(
                            vector![m[0], m[1]],
                            matrix![c[0], mean ; mean, c[3]],
                        )
                        .expect("Could not create the multivariate normal of the cluster")
                    })
                    .collect(),
            },
            PacketDistrJson::Udp { service, mu, cov } => PacketDistr::Udp {
                service: L7Proto::from_str(&service).unwrap(),
                distr: mu
                    .into_iter()
                    .zip(cov)
                    .map(|(m, c)| {
                        let c: Vec<f64> = c.into_iter().flatten().collect();
                        let mean = f64::midpoint(c[1], c[2]);
                        MultivariateNormal::new_from_nalgebra(
                            vector![m[0], m[1]],
                            matrix![c[0], mean ; mean, c[3]],
                        )
                        .expect("Could not create the multivariate normal of the cluster")
                    })
                    .collect(),
            },
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(tag = "proto")]
#[serde(rename_all = "UPPERCASE")]
enum PacketDistrJson {
    Tcp {
        conn_state: TcpConnState,
        service: String,
        mu: Vec<Vec<f64>>,
        cov: Vec<Vec<Vec<f64>>>,
    },
    Udp {
        service: String,
        mu: Vec<Vec<f64>>,
        cov: Vec<Vec<Vec<f64>>>,
    },
}

#[derive(Clone)]
pub struct TadamGenerator {
    lib: Arc<AutomataLibrary>,
}

impl TadamGenerator {
    pub fn new(lib: Arc<AutomataLibrary>) -> Self {
        TadamGenerator { lib }
    }
}

fn update_packet_counts<U: PacketInfo>(packets_info: &mut [U], flow: &mut FlowData) {
    flow.fwd_packets_count = packets_info
        .iter()
        .filter(|p| p.get_direction() == PacketDirection::Forward)
        .count();
    flow.bwd_packets_count = packets_info
        .iter()
        .filter(|p| p.get_direction() == PacketDirection::Backward)
        .count();
}

impl Stage3 for TadamGenerator {
    fn generate_tcp_packets_info(
        &self,
        mut flow: SeededData<FlowData>,
        conn_state: TcpConnState,
    ) -> Option<SeededData<PacketsIR<TcpPacketInfo>>> {
        let mut rng = Pcg32::seed_from_u64(flow.seed);
        let automata = self.lib.tcp_automata.get(&(flow.data.l7_proto, conn_state));

        // automata is found
        if let Some(vector) = automata {
            // choose a random automata among the list
            // this can only happen when using models from multiple models at once
            let AutomataSet { uncons_a, cons_a } = vector.choose(&mut rng).unwrap();
            let packets_info =
                automaton::sample(&mut rng, uncons_a, cons_a, &flow.data, create_tcp_header);

            if let Some(mut packets_info) = packets_info {
                update_packet_counts(&mut packets_info, &mut flow.data);

                Some(SeededData {
                    seed: rng.next_u64(),
                    data: PacketsIR::<TcpPacketInfo> {
                        packets_info,
                        flow: Flow::Tcp(flow.data, conn_state),
                    },
                })
            } else {
                log_once::warn_once!(
                    "Generation failure of automaton {:?}-{:?} for cluster {}",
                    flow.data.l7_proto,
                    conn_state,
                    flow.data.packets_count_cluster
                );
                None
            }
        } else {
            log_once::warn_once!(
                "No TCP automaton for {:?} with {:?}",
                flow.data.l7_proto,
                conn_state
            );
            None
        }
    }

    fn generate_udp_packets_info(
        &self,
        mut flow: SeededData<FlowData>,
    ) -> Option<SeededData<PacketsIR<UdpPacketInfo>>> {
        let mut rng = Pcg32::seed_from_u64(flow.seed);
        let automata = self.lib.udp_automata.get(&flow.data.l7_proto);
        // let a = self.lib.udp_automata.get(&flow.data.l7_proto);

        // automata is found
        if let Some(vector) = automata {
            let AutomataSet { uncons_a, cons_a } = vector.choose(&mut rng).unwrap();
            let packets_info =
                automaton::sample(&mut rng, uncons_a, cons_a, &flow.data, create_udp_header);

            if let Some(mut packets_info) = packets_info {
                update_packet_counts(&mut packets_info, &mut flow.data);

                Some(SeededData {
                    seed: rng.next_u64(),
                    data: PacketsIR::<UdpPacketInfo> {
                        packets_info,
                        flow: Flow::Udp(flow.data),
                    },
                })
            } else {
                None
            }
        } else {
            log_once::warn_once!("No UDP automaton for {:?}", flow.data.l7_proto);
            None
        }
    }

    fn generate_icmp_packets_info(
        &self,
        _flow: SeededData<FlowData>,
    ) -> Option<SeededData<PacketsIR<IcmpPacketInfo>>> {
        todo!()
    }
}
