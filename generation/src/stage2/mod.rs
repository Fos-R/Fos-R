#![allow(unused)]

use crate::structs::*;
use crate::tcp::*;
use crate::udp::*;
use crate::icmp::*;
use std::fs::File;
use std::fs;
use std::ffi::OsStr;
use std::path::PathBuf;
use rand_pcg::Pcg32;
use rand::prelude::*;
use std::net::Ipv4Addr;
use std::time::Duration;
use std::sync::Arc;

mod automaton;

pub struct Stage2 {
    lib: Arc<AutomataLibrary>,
}

pub struct AutomataLibrary {
    // TODO: map port -> automata
    tcp_automata: Vec<automaton::TimedAutomaton<TCPEdgeTuple>>,
    udp_automata: Vec<automaton::TimedAutomaton<UDPEdgeTuple>>,
    icmp_automata: Vec<automaton::TimedAutomaton<ICMPEdgeTuple>>,
}

impl Stage2 {

    pub fn new(lib: Arc<AutomataLibrary>) -> Self {
        Stage2 { lib }
    }


    pub fn generate_tcp_packets_info(&mut self, mut flow: SeededData<FlowData>) -> SeededData<PacketsIR<TCPPacketInfo>> {
        let mut rng = Pcg32::seed_from_u64(flow.seed);
        let automata = self.lib.tcp_automata.iter().find(|a| a.is_compatible_with(flow.data.dst_port)).expect(&format!("Fatal error: no automaton for destination port {}", flow.data.dst_port));
        let packets_info = automata.sample(&mut rng, flow.data.timestamp, create_tcp_header);

        // TODO
        flow.data.fwd_packets_count = packets_info.iter().filter(|p| p.direction == PacketDirection::Forward).count() as u32;
        flow.data.bwd_packets_count = packets_info.iter().filter(|p| p.direction == PacketDirection::Backward).count() as u32;
        flow.data.fwd_total_payload_length = packets_info.iter().filter(|p| p.direction == PacketDirection::Forward).map(|p| p.payload.get_payload_size()).sum::<usize>() as u32;
        flow.data.bwd_total_payload_length = packets_info.iter().filter(|p| p.direction == PacketDirection::Backward).map(|p| p.payload.get_payload_size()).sum::<usize>() as u32;
        flow.data.total_duration = packets_info.last().unwrap().ts - flow.data.timestamp;

        SeededData { seed: rng.next_u64(), data: PacketsIR::<TCPPacketInfo> { packets_info, flow: Flow::TCP(flow.data) } }
    }

    pub fn generate_udp_packets_info(&self, flow: SeededData<FlowData>) -> SeededData<PacketsIR<UDPPacketInfo>> {
        todo!()
    }

    pub fn generate_icmp_packets_info(&self, flow: SeededData<FlowData>) -> SeededData<PacketsIR<ICMPPacketInfo>> {
        todo!()
    }

}

pub fn import_automata_from_dir(directory_name: &str) -> AutomataLibrary {
    let mut nb = 0;
    let mut lib = AutomataLibrary { tcp_automata: vec![], udp_automata: vec![], icmp_automata: vec![] };

    let paths = fs::read_dir(directory_name).expect("Cannot read directory");
    for p in paths {
        let p = p.expect("Cannot open path").path();
        if !p.is_dir() && p.extension() == Some(OsStr::new("json")) {
            match import_automata(&mut lib, &p) {
                Ok(()) => {
                    log::info!("Automaton {:?} is loaded",p.file_name().unwrap());
                    nb += 1
                },
                Err(s) => log::error!("Could not load automaton {:?} ({})",p.file_name().unwrap(), s),
            }
        }
    }
    log::info!("{} automata have been loaded",nb);
    lib
}


pub fn import_automata(lib: &mut AutomataLibrary, filename: &PathBuf) -> std::io::Result<()> {
    let f = File::open(filename)?;
    let a : automaton::JsonAutomaton = serde_json::from_reader(f)?;
    match a.protocol {
        automaton::JsonProtocol::TCP => {
            lib.tcp_automata.push(automaton::TimedAutomaton::<TCPEdgeTuple>::import_timed_automaton(a,parse_tcp_symbol)); },
        automaton::JsonProtocol::UDP => {
            lib.udp_automata.push(automaton::TimedAutomaton::<UDPEdgeTuple>::import_timed_automaton(a,parse_udp_symbol)); },
        automaton::JsonProtocol::ICMP => {
            lib.icmp_automata.push(automaton::TimedAutomaton::<ICMPEdgeTuple>::import_timed_automaton(a,parse_icmp_symbol)); },
    }
    Ok(())
}


