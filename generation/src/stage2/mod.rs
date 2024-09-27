use crate::structs::*;
use std::fs::File;
use std::fs;
use std::ffi::OsStr;
use std::path::PathBuf;
use rand_pcg::Pcg32;
use rand::prelude::*;

mod automaton;

pub struct Stage2 {
    tcp_automata: Vec<automaton::TimedAutomaton<TCPPacketInfo>>,
    udp_automata: Vec<automaton::TimedAutomaton<UDPPacketInfo>>,
    icmp_automata: Vec<automaton::TimedAutomaton<ICMPPacketInfo>>,
    rng: Pcg32,
}

impl Stage2 {

    pub fn new(seed: u64) -> Self {
        Stage2 { tcp_automata: vec![], udp_automata: vec![], icmp_automata: vec![], rng: Pcg32::seed_from_u64(seed) }
    }

    pub fn import_automata_from_dir(&mut self, directory_name: &str) {
        let mut nb = 0;
        let paths = fs::read_dir(directory_name).expect("Cannot read directory");
        for p in paths {
            let p = p.expect("Cannot open path").path();
            if !p.is_dir() && p.extension() == Some(OsStr::new("json")) {
                match self.import_automata(&p) {
                    Ok(()) => {
                        println!("Automaton {:?} is loaded",p.file_name().unwrap());
                        nb += 1
                    },
                    Err(s) => println!("Could not load automaton {:?} ({})",p.file_name().unwrap(), s),
                }
            }
        }
        println!("{} automata have been loaded",nb);
    }

    pub fn import_automata(&mut self, filename: &PathBuf) -> std::io::Result<()> {
        let f = File::open(filename)?;
        let a : automaton::JsonAutomaton = serde_json::from_reader(f)?;
        match a.protocol {
            automaton::JsonProtocol::TCP => {
                self.tcp_automata.push(automaton::TimedAutomaton::<TCPPacketInfo>::import_timed_automaton(a,parse_tcp_symbol)); },
            automaton::JsonProtocol::UDP => {
                self.udp_automata.push(automaton::TimedAutomaton::<UDPPacketInfo>::import_timed_automaton(a,parse_udp_symbol)); },
            automaton::JsonProtocol::ICMP => {
                self.icmp_automata.push(automaton::TimedAutomaton::<ICMPPacketInfo>::import_timed_automaton(a,parse_icmp_symbol)); },
        }
        Ok(())
    }

    pub fn generate_tcp_packets_info(&mut self, flow: FlowData) -> PacketsIR<TCPPacketInfo> {
        // TODO: select correct TCP automata
        let packets_info = self.tcp_automata[0].sample(&mut self.rng);
        PacketsIR::<TCPPacketInfo> { packets_info, flow: Flow::TCPFlow(flow) }
    }

    pub fn generate_udp_packets_info(&self, flow: FlowData) -> PacketsIR<UDPPacketInfo> {
        panic!("Not implemented");
    }

    pub fn generate_icmp_packets_info(&self, flow: FlowData) -> PacketsIR<ICMPPacketInfo> {
        panic!("Not implemented");
    }

}
