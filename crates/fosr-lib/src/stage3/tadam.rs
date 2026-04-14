use crate::models;
use crate::stage3::*;

// use indicatif::{ProgressBar, ProgressStyle};
use nalgebra::{matrix, vector};
use rand_core::*;
use rand_pcg::Pcg32;
use serde::Deserialize;
use statrs::distribution::MultivariateNormal;
use std::collections::HashMap;
use std::sync::Arc;

struct AutomataSet<T: EdgeType> {
    cons_a: automaton::CrossProductTimedAutomaton<T>,
    uncons_a: automaton::TimedAutomaton<T>,
}

pub struct AutomataLibrary {
    tcp_automata: HashMap<(&'static str, TCPConnState), AutomataSet<TCPEdgeTuple>>,
    udp_automata: HashMap<&'static str, AutomataSet<UDPEdgeTuple>>,
    // cons_icmp_automata: HashMap<&'static str, automaton::CrossProductTimedAutomaton<ICMPEdgeTuple>>,
    // tcp_automata: HashMap<(&'static str, TCPConnState), automaton::TimedAutomaton<TCPEdgeTuple>>,
    // udp_automata: HashMap<&'static str, automaton::TimedAutomaton<UDPEdgeTuple>>,
    // icmp_automata: HashMap<&'static str, automaton::TimedAutomaton<ICMPEdgeTuple>>,
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
            // cons_tcp_automata: HashMap::new(),
            // cons_udp_automata: HashMap::new(),
            // cons_icmp_automata: HashMap::new(),
            tcp_automata: HashMap::new(),
            udp_automata: HashMap::new(),
            // icmp_automata: HashMap::new(),
        };

        for s in strings {
            match lib.import_from_str(&s, &clusters) {
                Ok(()) => nb += 1,
                Err(s) => log::error!("Could not load automaton ({})", s),
            }
            // pb.inc(1);
        }
        log::info!("{nb} automata have been loaded");
        Ok(lib)
    }

    pub fn import_from_str(
        &mut self,
        string: &str,
        clusters: &[PacketDistr],
    ) -> Result<(), String> {
        let string = string.to_string();
        let a: automaton::JsonAutomaton =
            serde_json::from_str::<automaton::JsonAutomaton>(string.leak())
                .map_err(|e| format!("Import error: {e}"))?;
        let l7proto = a.metadata.service.clone().leak();
        let conn_state = a.metadata.conn_state;
        match a.protocol {
            L4Proto::TCP => {
                assert!(conn_state.is_some());
                let automata_clusters = clusters
                    .iter()
                    .filter_map(|p| {
                        if let PacketDistr::TCP {
                            conn_state,
                            service,
                            distr,
                        } = p
                            && service == l7proto
                            && *conn_state == a.metadata.conn_state.unwrap()
                        {
                            Some(distr)
                        } else {
                            None
                        }
                    })
                    .next()
                    .unwrap_or_else(|| {
                        panic!(
                            "No cluster found for {l7proto} and {:?}",
                            conn_state.unwrap()
                        )
                    });
                assert!(!automata_clusters.is_empty());
                let a = automaton::TimedAutomaton::<TCPEdgeTuple>::import_timed_automaton(
                    a,
                    automata_clusters.clone(),
                    // automaton::IatPrecision::Milli,
                    parse_tcp_symbol,
                )?;
                log::debug!("Import TCP {a}");
                self.tcp_automata.insert(
                    (l7proto, conn_state.unwrap()),
                    AutomataSet {
                        uncons_a: a.clone(),
                        cons_a: a.into(),
                    },
                );
                // self.cons_tcp_automata
                // .insert((l7proto, conn_state.unwrap()), a.into());
            }
            L4Proto::UDP => {
                let automata_clusters = clusters
                    .iter()
                    .filter_map(|p| {
                        if let PacketDistr::UDP { service, distr } = p
                            && service == l7proto
                        {
                            Some(distr)
                        } else {
                            None
                        }
                    })
                    .next()
                    .expect("No cluster found for {l7proto}");

                assert!(!automata_clusters.is_empty());
                let a = automaton::TimedAutomaton::<UDPEdgeTuple>::import_timed_automaton(
                    a,
                    automata_clusters.clone(),
                    // automaton::IatPrecision::Micro,
                    parse_udp_symbol,
                )?;
                log::debug!("Import UDP {a}");
                self.udp_automata.insert(
                    l7proto,
                    AutomataSet {
                        uncons_a: a.clone(),
                        cons_a: a.into(),
                    },
                );
                // self.cons_udp_automata.insert(l7proto, a.into());
            }
            L4Proto::ICMP => todo!(), // {
                                      //     let a = automaton::TimedAutomaton::<ICMPEdgeTuple>::import_timed_automaton(
                                      //         a,
                                      //         // automaton::IatPrecision::Micro,
                                      //         parse_icmp_symbol,
                                      //     )?;
                                      //     log::debug!("Import ICMP {a}");
                                      //     // self.icmp_automata.insert(l7proto, a.clone());
                                      //     self.cons_icmp_automata.insert(l7proto, a.into());
                                      // }
        }
        Ok(())
    }
}

#[derive(Deserialize, Debug)]
#[serde(from = "PacketDistrJson")]
pub enum PacketDistr {
    TCP {
        conn_state: TCPConnState,
        service: String,
        distr: Vec<MultivariateNormal<nalgebra::Const<2>>>,
    },
    UDP {
        service: String,
        distr: Vec<MultivariateNormal<nalgebra::Const<2>>>,
    },
}

// Create the multivariate normal distribution on deserialization
impl From<PacketDistrJson> for PacketDistr {
    fn from(d: PacketDistrJson) -> Self {
        match d {
            PacketDistrJson::TCP {
                conn_state,
                service,
                mu,
                cov,
            } => PacketDistr::TCP {
                conn_state,
                service,
                distr: mu
                    .into_iter()
                    .zip(cov)
                    .map(|(m, c)| {
                        // Sometimes the covariance from sklearn’s GaussianMixture is not
                        // symmetric!
                        let c: Vec<f64> = c.into_iter().flatten().collect();
                        let mean = (c[1] + c[2]) / 2.;
                        MultivariateNormal::new_from_nalgebra(
                            vector![m[0], m[1]],
                            matrix![c[0],mean;mean,c[3]],
                        )
                        .expect("Could not create the multivariate normal of the cluster")
                    })
                    .collect(),
            },
            PacketDistrJson::UDP { service, mu, cov } => PacketDistr::UDP {
                service,
                distr: mu
                    .into_iter()
                    .zip(cov)
                    .map(|(m, c)| {
                        let c: Vec<f64> = c.into_iter().flatten().collect();
                        let mean = (c[1] + c[2]) / 2.;
                        MultivariateNormal::new_from_nalgebra(
                            vector![m[0], m[1]],
                            matrix![c[0],mean;mean,c[3]],
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
#[allow(clippy::upper_case_acronyms)]
enum PacketDistrJson {
    TCP {
        conn_state: TCPConnState,
        service: String,
        mu: Vec<Vec<f64>>,
        cov: Vec<Vec<Vec<f64>>>,
    },
    UDP {
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
        conn_state: TCPConnState,
    ) -> Option<SeededData<PacketsIR<TCPPacketInfo>>> {
        let mut rng = Pcg32::seed_from_u64(flow.seed);
        let automata = self.lib.tcp_automata.get(&(flow.data.l7_proto, conn_state));
        // let mut a = self.lib.tcp_automata.get(&(flow.data.l7_proto, conn_state));

        // if a.is_none() {
        //     a = self
        //         .lib
        //         .cons_tcp_automata
        //         .get(&(flow.data.l7_proto, TCPConnState::SF));
        //     // a = self
        //     //     .lib
        //     //     .tcp_automata
        //     //     .get(&(flow.data.l7_proto, TCPConnState::SF));
        //     if a.is_some() {
        //         conn_state = TCPConnState::SF;
        //     }
        // }

        // automata is found
        if let Some(AutomataSet { uncons_a, cons_a }) = automata {
            let packets_info =
                automaton::sample(&mut rng, uncons_a, cons_a, &flow.data, create_tcp_header);

            if let Some(mut packets_info) = packets_info {
                update_packet_counts(&mut packets_info, &mut flow.data);

                Some(SeededData {
                    seed: rng.next_u64(),
                    data: PacketsIR::<TCPPacketInfo> {
                        packets_info,
                        flow: Flow::TCP(flow.data, conn_state),
                    },
                })
            } else {
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
    ) -> Option<SeededData<PacketsIR<UDPPacketInfo>>> {
        let mut rng = Pcg32::seed_from_u64(flow.seed);
        let automata = self.lib.udp_automata.get(&flow.data.l7_proto);
        // let a = self.lib.udp_automata.get(&flow.data.l7_proto);

        // automata is found
        if let Some(AutomataSet { uncons_a, cons_a }) = automata {
            let packets_info =
                automaton::sample(&mut rng, uncons_a, cons_a, &flow.data, create_udp_header);

            if let Some(mut packets_info) = packets_info {
                update_packet_counts(&mut packets_info, &mut flow.data);

                Some(SeededData {
                    seed: rng.next_u64(),
                    data: PacketsIR::<UDPPacketInfo> {
                        packets_info,
                        flow: Flow::UDP(flow.data),
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
    ) -> Option<SeededData<PacketsIR<ICMPPacketInfo>>> {
        todo!()
    }
}
