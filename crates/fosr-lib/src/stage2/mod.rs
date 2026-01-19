use crate::stats::Stats;
use crate::structs::*;
use crossbeam_channel::{Receiver, Sender};
use rand_core::*;
use std::net::Ipv4Addr;
use std::sync::Arc;

/// A implementation of Bayesian networks generation
pub mod bayesian_networks;
mod bifxml;

// /// A implementation of FlowChronicle’s generation
// pub mod flowchronicle;

/// A trait for Stage 1 that generates flow descriptions
pub trait Stage2: Clone + std::marker::Send + 'static {
    /// Generate flow(s) from a starting timestamp
    fn generate_flows(
        &self,
        ts: SeededData<TimePoint>,
    ) -> Result<impl Iterator<Item = SeededData<Flow>>, String>;
}

/// Generate flows from timestamps and sends them progressively to a channel
pub fn run_channel(
    generator: impl Stage2,
    rx_s1: Receiver<SeededData<TimePoint>>,
    tx_s1: Sender<SeededData<Flow>>,
    stats: Arc<Stats>,
) -> Result<(), Box<dyn std::error::Error>> {
    log::trace!("Start S1");
    for ts in rx_s1 {
        if stats.should_stop() {
            break;
        }
        for f in generator.generate_flows(ts)? {
            tx_s1.send(f)?;
        }
    }
    log::trace!("S1 stops");
    Ok(())
}

/// Generate flows from timestamps and into a vector
pub fn run_vec(
    generator: impl Stage2,
    vec_s1: Vec<SeededData<TimePoint>>,
) -> Result<Vec<SeededData<Flow>>, String> {
    log::trace!("Start S1");
    let mut vector = Vec::with_capacity(vec_s1.len());
    for ts in vec_s1 {
        for f in generator.generate_flows(ts)? {
            vector.push(f);
        }
    }
    log::trace!("S1 stops");
    Ok(vector)
}

/// A structure used to drop generated flow that are irrelevant in a network injection scenario
#[derive(Debug, Clone)]
pub struct FilterForOnline<T: Stage2> {
    ips_to_keep: Vec<Ipv4Addr>,
    s1: T,
}

impl<T: Stage2> FilterForOnline<T> {
    pub fn new(ips_to_keep: Vec<Ipv4Addr>, s1: T) -> Self {
        FilterForOnline { ips_to_keep, s1 }
    }
}

impl<T: Stage2> Stage2 for FilterForOnline<T> {
    fn generate_flows(
        &self,
        ts: SeededData<TimePoint>,
    ) -> Result<impl Iterator<Item = SeededData<Flow>>, String> {
        Ok(self.s1.generate_flows(ts)?.filter(|f| {
            let data = f.data.get_data();
            let kept =
                self.ips_to_keep.contains(&data.src_ip) || self.ips_to_keep.contains(&data.dst_ip);
            if kept {
                log::trace!("{} -> {} (kept)", data.src_ip, data.dst_ip);
            } else {
                log::trace!("{} -> {} (dropped)", data.src_ip, data.dst_ip);
            }
            kept
        }))
    }
}
