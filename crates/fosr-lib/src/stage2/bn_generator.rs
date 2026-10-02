use crate::models;
use crate::network;
use crate::stage2::bayesian_networks::*;
use crate::stage2::bn_structs::*;
use crate::stage2::{Stage2, TimePoint, bifxml};
use crate::structs::{DstIpRole, Flow, L7Proto, OS, Port, SeededData, SrcIpRole};

use chrono::Timelike;
use pnet::util::MacAddr;
use rand::prelude::SliceRandom;
use rand_core::{Rng, SeedableRng};
use rand_distr::Distribution;
use rand_distr::Uniform;
use rand_distr::weighted::WeightedIndex;
use rand_pcg::Pcg32;
use std::cmp::min;
use std::collections::HashMap;
use std::iter;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::RwLock;
use strum::IntoEnumIterator;

/// Stage 1: generates flow descriptions
#[derive(Clone)]
#[allow(unused)]
pub struct BNGenerator {
    model: Arc<RwLock<BayesianModel>>,
    online: bool, // used to generate the TTL, either initial or at the capture point
}

impl BNGenerator {
    pub fn new(model: Arc<RwLock<BayesianModel>>, online: bool) -> Self {
        BNGenerator { model, online }
    }
}

impl Stage2 for BNGenerator {
    /// Generates flows
    fn generate_flows(
        &self,
        ts: SeededData<TimePoint>,
    ) -> Result<impl Iterator<Item = SeededData<Flow>>, String> {
        let mut rng = Pcg32::seed_from_u64(ts.seed);
        let mut domain_vector: IntermediateVector = IntermediateVector::default();

        let model = self.model.read().unwrap();
        let bin_count = model.get_bin_count();
        let mut restart = true;
        let bn = model.get_bn()?;
        while restart {
            // TODO: idéalement, plus besoin de restart…
            restart = false;
            let time = min(
                bin_count - 1,
                ((f64::from(ts.data.date_time.num_seconds_from_midnight()) / (3600. * 24.)).fract()
                    * (bin_count as f64)) as usize,
            );
            let discrete_vector: Vec<usize> = vec![time];
            domain_vector = if model.get_tl()?.is_some() {
                bn.sample_transfer_learning(&mut rng, discrete_vector)?
            } else {
                bn.sample_in_domain(&mut rng, discrete_vector)?
            };

            if domain_vector.src_ip.is_some() && domain_vector.src_ip == domain_vector.dst_ip {
                log::trace!("Restart (identical IPs)");
                restart = true;
                continue;
            }

            domain_vector.timestamp = Some(ts.data.unix_time);
            let uniform = domain_vector.src_os.unwrap().get_ephemeral_port_distr();
            // Use the default source port for that protocol if that exists
            domain_vector.src_port = Some(
                match domain_vector.l7_proto.unwrap().get_default_src_port() {
                    Port::Fixed(p) => p,
                    Port::Random => uniform.sample(&mut rng),
                },
            );

            let port = domain_vector
                .l7_proto
                .unwrap()
                .get_default_dst_port()
                .unwrap();
            // TODO: discutable
            let uniform = domain_vector.dst_os.unwrap().get_ephemeral_port_distr();
            domain_vector.dst_port = Some(match port {
                Port::Fixed(p) => p,
                Port::Random => uniform.sample(&mut rng),
            });

            if let Some(tl) = model.get_tl()? {
                // // Sample the destination IP
                // let dst_ips = tl.dst_ip.get(&(
                //     domain_vector.l7_proto.unwrap(),
                //     domain_vector.dst_os.unwrap(),
                //     domain_vector.dst_ip_role.unwrap(),
                // ));
                // if let Some((ips, weights)) = dst_ips {
                //     // This combinaison of L7 proto, OS and Role is known
                //     let ip = *ips.get(weights.sample(&mut rng)).unwrap();
                //     domain_vector.dst_ip = Some(match ip {
                //         AnonymizedIpv4Addr::Known(ip) => ip,
                //         AnonymizedIpv4Addr::Public => utils::sample_random_global_ip(&mut rng),
                //     });
                // } else {
                //     // This combinaison is not known: we cannot sample it
                //     log::error!(
                //         "No Destination IP for {}, {}, {:?}",
                //         domain_vector.l7_proto.unwrap(),
                //         domain_vector.dst_os.unwrap(),
                //         domain_vector.dst_ip_role.unwrap()
                //     );
                //     restart = true;
                //     continue;
                // };

                // // Sample the source IP
                // let src_ips = tl.src_ip.get(&(
                //     domain_vector.l7_proto.unwrap(),
                //     domain_vector.src_os.unwrap(),
                //     domain_vector.src_ip_role.unwrap(),
                // ));
                // if let Some((ips, weights)) = src_ips {
                //     // This combinaison of L7 proto, OS and Role is known
                //     let ip = *ips.get(weights.sample(&mut rng)).unwrap();
                //     domain_vector.src_ip = Some(match ip {
                //         AnonymizedIpv4Addr::Known(ip) => ip,
                //         AnonymizedIpv4Addr::Public => utils::sample_random_global_ip(&mut rng),
                //     });
                // } else {
                //     // This combinaison is not known: we cannot sample it
                //     log::error!(
                //         "No Source IP for {}, {}, {:?}",
                //         domain_vector.l7_proto.unwrap(),
                //         domain_vector.src_os.unwrap(),
                //         domain_vector.src_ip_role.unwrap()
                //     );
                //     restart = true;
                //     continue;
                // };

                domain_vector.src_mac = Some(
                    *tl.mac_addr_map
                        .get(&domain_vector.src_ip.unwrap())
                        .unwrap_or(&MacAddr::zero()),
                ); // TODO
                domain_vector.dst_mac = Some(
                    *tl.mac_addr_map
                        .get(&domain_vector.dst_ip.unwrap())
                        .unwrap_or(&MacAddr::zero()),
                ); // TODO

                let port = match tl.services_per_server.get(&(
                    domain_vector.dst_ip.unwrap(),
                    domain_vector.l7_proto.unwrap(),
                )) {
                    // local IPs
                    Some(v) => v.first().unwrap().get_port(),
                    // public IPs
                    None => domain_vector
                        .l7_proto
                        .unwrap()
                        .get_default_dst_port()
                        .unwrap(),
                };
                // TODO: Discutable...
                let uniform = domain_vector.dst_os.unwrap().get_ephemeral_port_distr();
                domain_vector.dst_port = Some(match port {
                    Port::Fixed(p) => p,
                    Port::Random => uniform.sample(&mut rng),
                });

                // Complete TTL
                domain_vector.src_ttl = Some(
                    // TODO: we can do better
                    domain_vector.src_os.unwrap().get_initial_ttl()
                        - *tl
                            .local_ttl_delta
                            .get(&domain_vector.src_ip.unwrap())
                            .unwrap_or(&Uniform::new(0, 10).unwrap().sample(&mut rng)),
                );
                domain_vector.dst_ttl = Some(
                    domain_vector.dst_os.unwrap().get_initial_ttl()
                        - *tl
                            .local_ttl_delta
                            .get(&domain_vector.dst_ip.unwrap())
                            .unwrap_or(&Uniform::new(0, 10).unwrap().sample(&mut rng)),
                );
            }
        }
        Ok(iter::once(SeededData {
            seed: rng.next_u64(),
            data: domain_vector.into(),
        }))
    }
}

/// The model with all the data
#[derive(Clone)]
#[allow(clippy::large_enum_variant)]
pub enum BayesianModel {
    DatasetSpecific {
        bn: BayesianNetwork,
        bin_count: usize,
    },
    ForTransferLearning {
        base_bn: BayesianNetwork,
        bn: BayesianNetwork,
        bin_count: usize,
        transfer_learning: TransferLearningExtraData,
    },
    WaitingForNetwork {
        base_bn: BayesianNetwork,
        bin_count: usize,
    },
}

impl BayesianModel {
    pub fn from_source_for_transfer_learning(
        m: &models::ModelsSource,
        alpha: u64,
    ) -> Result<Self, String> {
        // We use a seeded RNG so everything is deterministic

        let bn_string: String = m
            .get_tl_bn()
            .map_err(|e| format!("Cannot find the Bayesian networks: {e}"))?;

        log::trace!("Loading Bayesian network");
        let bif_common = bifxml::from_str(&bn_string)?;

        log::trace!("Converting from BIF");
        let (base_bn, bin_count) = bn_from_bif(bif_common, alpha)?;

        log::info!("Bayesian network has been loaded");
        Ok(BayesianModel::WaitingForNetwork { base_bn, bin_count })
    }

    pub fn with_network(&self, network: &network::Network) -> Result<Self, String> {
        match self {
            BayesianModel::WaitingForNetwork {
                base_bn, bin_count, ..
            }
            | BayesianModel::ForTransferLearning {
                base_bn, bin_count, ..
            } => {
                let mut bn = base_bn.clone();

                bn.update_probabilities(network);

                bn.remove_impossible_values()?;

                let mut rng = Pcg32::seed_from_u64(12345);
                let mut src_ip: HashMap<(L7Proto, OS, SrcIpRole), AnonymizedIpv4Distr> =
                    HashMap::new();
                let mut dst_ip: HashMap<(L7Proto, OS, DstIpRole), AnonymizedIpv4Distr> =
                    HashMap::new();

                if network.users.is_empty() {
                    return Err("No client in the network".to_string());
                }
                if network.servers.is_empty() {
                    return Err("No server in the network".to_string());
                }
                // TODO: plutôt que d’avoir une erreur, plutôt mettre à jour le réseau bayésien

                for s in &network.services {
                    for os in OS::iter() {
                        for role in SrcIpRole::iter() {
                            if let Some(ips) = network.users.get(&(os, role)) {
                                src_ip.insert(
                                    (*s, os, role),
                                    match role {
                                        SrcIpRole::Internet if network.has_internet_access =>
                                        // It can be a known Internet host, or just "Internet"
                                        {
                                            (
                                                ips.clone()
                                                    .into_iter()
                                                    .map(AnonymizedIpv4Addr::Known)
                                                    // add Internet
                                                    .chain(iter::once(AnonymizedIpv4Addr::Public))
                                                    .collect(),
                                                get_zipf_weights_with_extra_value(
                                                    ips.len(),
                                                    &mut rng,
                                                    0.8, // TODO: do not hardcode
                                                ),
                                            )
                                        }
                                        _ => (
                                            ips.clone()
                                                .into_iter()
                                                .map(AnonymizedIpv4Addr::Known)
                                                .collect(),
                                            get_zipf_weights(ips.len(), &mut rng),
                                        ),
                                    },
                                );
                            } else if network.has_internet_access {
                                // Only Internet
                                src_ip.insert(
                                    (*s, os, role),
                                    (
                                        vec![AnonymizedIpv4Addr::Public],
                                        WeightedIndex::new([1.0]).unwrap(),
                                    ),
                                );
                            } // No "else" arm: if the role is Internet but there is no Internet-reachable IPs and
                            // there is no Internet access, then there is no possible IPs
                        }

                        for role in DstIpRole::iter() {
                            let ips = network.servers.get(&(*s, os, role));
                            if let Some(ips) = ips {
                                dst_ip.insert(
                                    (*s, os, role),
                                    match role {
                                        DstIpRole::Internet if network.has_internet_access => {
                                            // A known Internet host, or just "Internet"
                                            (
                                                ips.clone()
                                                    .into_iter()
                                                    .map(AnonymizedIpv4Addr::Known)
                                                    // add Internet
                                                    .chain(iter::once(AnonymizedIpv4Addr::Public))
                                                    .collect(),
                                                get_zipf_weights_with_extra_value(
                                                    ips.len(),
                                                    &mut rng,
                                                    0.8, // TODO: do not hardcode
                                                ),
                                            )
                                        }
                                        _ => (
                                            ips.clone()
                                                .into_iter()
                                                .map(AnonymizedIpv4Addr::Known)
                                                .collect(),
                                            get_zipf_weights(ips.len(), &mut rng),
                                        ),
                                    },
                                );
                            } else if network.has_internet_access {
                                // Only Internet
                                dst_ip.insert(
                                    (*s, os, role),
                                    (
                                        vec![AnonymizedIpv4Addr::Public],
                                        WeightedIndex::new([1.0]).unwrap(),
                                    ),
                                );
                            }
                        }
                    }
                }

                let mut local_ttl_delta: HashMap<Ipv4Addr, u8> = HashMap::new();
                let mut mac_addr_map = network.mac_addr_map.clone();
                for ip in network.all_ips.iter() {
                    // TODO ! TTL should be calculated from the topology
                    local_ttl_delta.insert(*ip, (rng.next_u32() % 10) as u8);
                    if !mac_addr_map.contains_key(ip) {
                        mac_addr_map.insert(
                            *ip,
                            // TODO: MacAddr are not fully random
                            MacAddr::new(
                                rng.next_u32() as u8,
                                rng.next_u32() as u8,
                                rng.next_u32() as u8,
                                rng.next_u32() as u8,
                                rng.next_u32() as u8,
                                rng.next_u32() as u8,
                            ),
                        );
                    }
                }

                bn.add_tl_nodes(src_ip, dst_ip, &network.all_ips);
                let tl_extra_data = TransferLearningExtraData {
                    // src_ip,
                    // dst_ip,
                    local_ttl_delta,
                    services_per_server: network.services_per_server.clone(),
                    mac_addr_map,
                };

                Ok(BayesianModel::ForTransferLearning {
                    base_bn: base_bn.clone(),
                    bn,
                    bin_count: *bin_count,
                    transfer_learning: tl_extra_data,
                })
            }
            BayesianModel::DatasetSpecific { .. } => Err(
                "A model suited for transfer learning is mandatory to use a custom network"
                    .to_string(),
            ),
        }
    }

    pub fn from_source(m: &models::ModelsSource, alpha: u64) -> Result<Self, String> {
        let bn_string: String = m
            .get_bn()
            .map_err(|e| format!("Cannot find the Bayesian networks: {e}"))?;

        log::trace!("Loading Bayesian network");
        let bif_common = bifxml::from_str(&bn_string)?;

        log::trace!("Converting from BIF");
        let (mut bn, bin_count) = bn_from_bif(bif_common, alpha)?;

        log::info!("Bayesian network has been loaded");
        bn.remove_impossible_values()?;

        // log::info!("{bn_common}");
        Ok(BayesianModel::DatasetSpecific { bn, bin_count })
    }

    fn get_bin_count(&self) -> usize {
        match self {
            BayesianModel::DatasetSpecific { bin_count, .. }
            | BayesianModel::ForTransferLearning { bin_count, .. }
            | BayesianModel::WaitingForNetwork { bin_count, .. } => *bin_count,
        }
    }

    fn get_bn(&self) -> Result<&BayesianNetwork, String> {
        match self {
            BayesianModel::DatasetSpecific { bn, .. }
            | BayesianModel::ForTransferLearning { bn, .. } => Ok(bn),
            BayesianModel::WaitingForNetwork { .. } => {
                Err("A network must be specified before this model can be used".to_string())
            }
        }
    }

    fn get_tl(&self) -> Result<Option<&TransferLearningExtraData>, String> {
        match self {
            BayesianModel::DatasetSpecific { .. } => Ok(None),
            BayesianModel::ForTransferLearning {
                transfer_learning, ..
            } => Ok(Some(transfer_learning)),
            BayesianModel::WaitingForNetwork { .. } => {
                Err("A network must be specified before this model can be used".to_string())
            }
        }
    }
}

/// A Zipf distribution for client and server activity
fn get_zipf_weights(len: usize, rng: &mut impl Rng) -> WeightedIndex<f64> {
    assert!(len > 0);
    let mut weights: Vec<f64> = iter::repeat_n(1, len)
        .enumerate()
        .map(|(i, _)| 1. / ((i + 1) as f64))
        .collect();
    weights.shuffle(rng);
    WeightedIndex::new(&weights).unwrap()
}

/// A Zipf distribution, except for one value that has a fixed probability.
/// This extra value will alway be at the end of the list.
fn get_zipf_weights_with_extra_value(
    len: usize,
    rng: &mut impl Rng,
    probability: f64,
) -> WeightedIndex<f64> {
    assert!(len > 0);
    assert!(probability >= 0.0);
    assert!(probability < 1.0);
    let mut weights: Vec<f64> = iter::repeat_n(1, len)
        .enumerate()
        .map(|(i, _)| 1. / ((i + 1) as f64))
        .collect();
    weights.shuffle(rng);
    let extra_weight = weights.iter().sum::<f64>() * probability / (1.0 - probability);
    weights.push(extra_weight);
    WeightedIndex::new(&weights).unwrap()
}
