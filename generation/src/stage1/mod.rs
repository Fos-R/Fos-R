use crate::structs::*;
use std::time::Duration;
use std::net::Ipv4Addr;
use crossbeam_channel::{Sender, Receiver};

pub mod flowchronicle;

/// Stage 1: generates flow descriptions
pub trait Stage1: Clone + std::marker::Send + 'static {
    fn generate_flows(&self, ts: SeededData<Duration>) -> Vec<SeededData<Flow>>;
}

pub fn run(generator: impl Stage1, rx_s1: Receiver<SeededData<Duration>>, tx_s1: Sender<SeededData<Flow>>, local_interfaces: Vec<Ipv4Addr>) {
    log::trace!("Start S1");
    while let Ok(ts) = rx_s1.recv() {
        let flows = generator.generate_flows(ts).into_iter();
        log::trace!("S1 generates {:?}", flows);
        // TODO: verify logic (wait if we save pcap too?)
        if !local_interfaces.is_empty() { // only keep relevant flows
            flows.filter(|f| {
                let data = f.data.get_data();
                local_interfaces.contains(&data.src_ip) || local_interfaces.contains(&data.dst_ip)
            }).for_each(|f| tx_s1.send(f).unwrap());
        } else {
            flows.for_each(|f| tx_s1.send(f).unwrap());
        }
    }
    log::trace!("S1 stops");
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

    fn generate_flows(&self, ts: SeededData<Duration>) -> Vec<SeededData<Flow>> {
        let flow = Flow::TCP(FlowData {
            src_ip: self.src_ip,
            dst_ip: self.dst_ip,
            src_port: 34200,
            dst_port: 21,
            ttl_client: 23,
            ttl_server: 68,
            fwd_packets_count: 3,
            bwd_packets_count: 2,
            fwd_total_payload_length: 122,
            bwd_total_payload_length: 88,
            timestamp: ts.data,
            total_duration: Duration::from_millis(2300),
            } );
        vec![SeededData { seed: ts.seed, data: flow }]
    }

}

