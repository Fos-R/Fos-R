use crate::config::Hosts;
use crate::structs::*;
use crate::ui::Stats;
use crossbeam_channel::{Receiver, Sender};
use rand_core::*;
use rand_pcg::Pcg32;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

pub mod bayesian_networks;
pub mod flowchronicle;

/// Stage 1: generates flow descriptions
pub trait Stage1: Clone + std::marker::Send + 'static {
    fn generate_flows(&self, ts: SeededData<TimePoint>) -> impl Iterator<Item = SeededData<Flow>>;
}

pub fn run(
    generator: impl Stage1,
    rx_s1: Receiver<SeededData<TimePoint>>,
    tx_s1: Sender<SeededData<Flow>>,
    stats: Arc<Stats>,
) -> Result<(), Box<dyn std::error::Error>> {
    log::trace!("Start S1");
    for ts in rx_s1 {
        if stats.should_stop() {
            break;
        }
        for f in generator.generate_flows(ts) {
            tx_s1.send(f)?;
        }
    }
    log::trace!("S1 stops");
    Ok(())
}

#[derive(Debug, Clone)]
pub struct FilterForOnline<T: Stage1> {
    ips_to_keep: Vec<Ipv4Addr>,
    s1: T,
}

impl<T: Stage1> FilterForOnline<T> {
    pub fn new(ips_to_keep: Vec<Ipv4Addr>, s1: T) -> Self {
        FilterForOnline { ips_to_keep, s1 }
    }
}

impl<T: Stage1> Stage1 for FilterForOnline<T> {
    fn generate_flows(&self, ts: SeededData<TimePoint>) -> impl Iterator<Item = SeededData<Flow>> {
        self.s1.generate_flows(ts).filter(|f| {
            let data = f.data.get_data();
            let kept =
                self.ips_to_keep.contains(&data.src_ip) || self.ips_to_keep.contains(&data.dst_ip);
            if kept {
                log::trace!("{} -> {} (kept)", data.src_ip, data.dst_ip);
            } else {
                log::trace!("{} -> {} (dropped)", data.src_ip, data.dst_ip);
            }
            kept
        })
    }
}

// #[derive(Debug, Clone)]
// pub struct ConfigBasedModifier<T: Stage1> {
//     conf: Hosts,
//     s1: T,
// }

// impl<T: Stage1> ConfigBasedModifier<T> {
//     pub fn new(conf: Hosts, s1: T) -> Self {
//         ConfigBasedModifier { conf, s1 }
//     }

//     fn modify_flow(&self, mut f: SeededData<Flow>) -> SeededData<Flow> {
//         let mut rng = Pcg32::seed_from_u64(f.seed);
//         let src_and_dst_ips = self
//             .conf
//             .get_src_and_dst_ip(&mut rng, f.data.get_data().dst_port);
//         if let Some((src_ip, dst_ip)) = src_and_dst_ips {
//             let dataflow = f.data.get_data_mut();
//             dataflow.src_ip = src_ip;
//             dataflow.dst_ip = dst_ip;
//         }
//         // TODO: et si c’est pas le cas ?
//         SeededData {
//             seed: rng.next_u64(),
//             data: f.data,
//         }
//     }
// }

// impl<T: Stage1> Stage1 for ConfigBasedModifier<T> {
//     fn generate_flows(&self, ts: SeededData<TimePoint>) -> impl Iterator<Item = SeededData<Flow>> {
//         self.s1.generate_flows(ts).map(move |f| self.modify_flow(f))
//     }
// }
