use crate::tcp::*;
use crate::udp::*;
use crate::icmp::*;
use crate::stage2::*;
use std::fs::File;
use std::fs;
use std::ffi::OsStr;
use std::path::PathBuf;
use rand_pcg::Pcg32;
use rand::prelude::*;
use std::sync::Arc;

pub struct AutomataLibrary {
    // TODO: map port -> automata
    tcp_automata: Vec<automaton::CrossProductTimedAutomaton<TCPEdgeTuple>>,
    udp_automata: Vec<automaton::CrossProductTimedAutomaton<UDPEdgeTuple>>,
    icmp_automata: Vec<automaton::CrossProductTimedAutomaton<ICMPEdgeTuple>>,
}

impl AutomataLibrary {

    #[allow(unused)]
    pub fn default_library() -> Self {
        // TODO: utiliser include_str pour mettre les automates par défaut
        AutomataLibrary { tcp_automata: vec![], udp_automata: vec![], icmp_automata: vec![] }
    }

    pub fn from_dir(directory_name: &str) -> Self {
        let mut nb = 0;
        let mut lib = AutomataLibrary { tcp_automata: vec![], udp_automata: vec![], icmp_automata: vec![] };

        let paths = fs::read_dir(directory_name).expect("Cannot read directory");
        for p in paths {
            let p = p.expect("Cannot open path").path();
            if !p.is_dir() && p.extension() == Some(OsStr::new("json")) {
                match lib.import_from_file(&p) {
                    Ok(()) => {
                        log::debug!("Automaton {:?} is loaded",p.file_name().unwrap());
                        nb += 1
                    },
                    Err(s) => log::error!("Could not load automaton {:?} ({})",p.file_name().unwrap(), s),
                }
            }
        }
        log::info!("{} automata have been loaded",nb);
        lib
    }

    pub fn import_from_file(&mut self, filename: &PathBuf) -> std::io::Result<()> {
        let f = File::open(filename)?;
        let a : automaton::JsonAutomaton = serde_json::from_reader(f)?;
        match a.protocol {
            Protocol::TCP => {
                self.tcp_automata.push(automaton::TimedAutomaton::<TCPEdgeTuple>::import_timed_automaton(a,parse_tcp_symbol).into()); },
            Protocol::UDP => {
                self.udp_automata.push(automaton::TimedAutomaton::<UDPEdgeTuple>::import_timed_automaton(a,parse_udp_symbol).into()); },
            Protocol::ICMP => {
                self.icmp_automata.push(automaton::TimedAutomaton::<ICMPEdgeTuple>::import_timed_automaton(a,parse_icmp_symbol).into()); },
        }
        Ok(())
    }

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

#[allow(unused)]
impl Stage2 for TadamGenerator {

    fn generate_tcp_packets_info(&self, mut flow: SeededData<FlowData>) -> SeededData<PacketsIR<TCPPacketInfo>> {
        let mut rng = Pcg32::seed_from_u64(flow.seed);
        let automata = self.lib.tcp_automata.iter().find(|a| a.is_compatible_with(flow.data.dst_port));

        match automata {
            None => {
                log::error!("No automaton for destination port {}", flow.data.dst_port);
                todo!() // TODO: trouver comment gérer ce cas
            }
            Some(automata) => {
                let packets_info = automata.sample(&mut rng, &flow.data, create_tcp_header);

                // Depending on the automata, the packets count may not be exact, so we need to
                // update it
                flow.data.fwd_packets_count = packets_info.iter().filter(|p| p.direction == PacketDirection::Forward).count();
                flow.data.bwd_packets_count = packets_info.iter().filter(|p| p.direction == PacketDirection::Backward).count();
                flow.data.fwd_total_payload_length = packets_info.iter().filter(|p| p.direction == PacketDirection::Forward).map(|p| p.payload.get_payload_size()).sum::<usize>() as u32;
                flow.data.bwd_total_payload_length = packets_info.iter().filter(|p| p.direction == PacketDirection::Backward).map(|p| p.payload.get_payload_size()).sum::<usize>() as u32;
                flow.data.total_duration = packets_info.last().unwrap().ts - flow.data.timestamp;

                SeededData { seed: rng.next_u64(), data: PacketsIR::<TCPPacketInfo> { packets_info, flow: Flow::TCP(flow.data) } }
            }
        }
    }

    fn generate_udp_packets_info(&self, flow: SeededData<FlowData>) -> SeededData<PacketsIR<UDPPacketInfo>> {
        todo!()
    }

    fn generate_icmp_packets_info(&self, flow: SeededData<FlowData>) -> SeededData<PacketsIR<ICMPPacketInfo>> {
        todo!()
    }

}
