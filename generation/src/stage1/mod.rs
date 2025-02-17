use crate::config::Hosts;
use crate::structs::*;
use crossbeam_channel::{Receiver, Sender};
use rand_core::*;
use rand_pcg::Pcg32;
use std::net::Ipv4Addr;
use std::time::Duration;

pub mod flowchronicle;

/// Stage 1: generates flow descriptions
pub trait Stage1: Clone + std::marker::Send + 'static {
    fn generate_flows(&self, ts: SeededData<Duration>) -> impl Iterator<Item = SeededData<Flow>>;
}

pub fn run(
    generator: impl Stage1,
    rx_s1: Receiver<SeededData<Duration>>,
    tx_s1: Sender<SeededData<Flow>>,
) {
    log::trace!("Start S1");
    for ts in rx_s1 {
        generator
            .generate_flows(ts)
            .for_each(|f| tx_s1.send(f).unwrap());
    }
    log::trace!("S1 stops");
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
    fn generate_flows(&self, ts: SeededData<Duration>) -> impl Iterator<Item = SeededData<Flow>> {
        self.s1.generate_flows(ts).filter(|f| {
            let data = f.data.get_data();
            self.ips_to_keep.contains(&data.src_ip) || self.ips_to_keep.contains(&data.dst_ip)
        })
    }
}

#[derive(Debug, Clone)]
pub struct ConfigBasedModifier<T: Stage1> {
    conf: Hosts,
    s1: T,
}

impl<T: Stage1> ConfigBasedModifier<T> {
    pub fn new(conf: Hosts, s1: T) -> Self {
        ConfigBasedModifier { conf, s1 }
    }

    fn modify_flow(&self, mut f: SeededData<Flow>) -> SeededData<Flow> {
        let mut rng = Pcg32::seed_from_u64(f.seed);
        let src_and_dst_ips = self
            .conf
            .get_src_and_dst_ip(&mut rng, f.data.get_data().dst_port);
        if let Some((src_ip, dst_ip)) = src_and_dst_ips {
            let dataflow = f.data.get_data_mut();
            dataflow.src_ip = src_ip;
            dataflow.dst_ip = dst_ip;
        }
        // TODO: et si c’est pas le cas ?
        SeededData {
            seed: rng.next_u64(),
            data: f.data,
        }
    }
}

impl<T: Stage1> Stage1 for ConfigBasedModifier<T> {
    fn generate_flows(&self, ts: SeededData<Duration>) -> impl Iterator<Item = SeededData<Flow>> {
        self.s1.generate_flows(ts).map(move |f| self.modify_flow(f))
    }
}

#[derive(Debug, Clone)]
pub struct ConstantFlowGenerator {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
}

impl ConstantFlowGenerator {
    pub fn new(src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> Self {
        ConstantFlowGenerator { src_ip, dst_ip }
    }
}

impl Stage1 for ConstantFlowGenerator {
    fn generate_flows(&self, ts: SeededData<Duration>) -> impl Iterator<Item = SeededData<Flow>> {
        let flow = Flow::TCP(FlowData {
            src_ip: self.src_ip,
            dst_ip: self.dst_ip,
            src_port: 34200,
            dst_port: 21,
            ttl_client: 23,
            ttl_server: 68,
            fwd_packets_count: 15,
            bwd_packets_count: 10,
            timestamp: ts.data,
            // total_duration: Duration::from_millis(2300),
        });
        vec![SeededData {
            seed: ts.seed,
            data: flow,
        }]
        .into_iter()
    }
}
