use crate::structs::*;
use std::fs::File;
mod automaton;

pub struct Stage2 {
    tcp_automata: Vec<automaton::TimedAutomaton<TCPPacketInfo>>,
    udp_automata: Vec<automaton::TimedAutomaton<UDPPacketInfo>>,
    icmp_automata: Vec<automaton::TimedAutomaton<ICMPPacketInfo>>
}

impl Stage2 {

    pub fn new() -> Self {
        Stage2 { tcp_automata: vec![], udp_automata: vec![], icmp_automata: vec![] }
    }

    pub fn import_automata(&mut self, filename: &str) -> std::io::Result<()> {
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

    pub fn generate_tcp_packets_info(&self, flow: &FlowData) -> PacketsIR<TCPPacketInfo> {
        panic!("Not implemented");
    }

    pub fn generate_udp_packets_info(&self, flow: &FlowData) -> PacketsIR<UDPPacketInfo> {
        panic!("Not implemented");
    }

    pub fn generate_icmp_packets_info(&self, flow: &FlowData) -> PacketsIR<ICMPPacketInfo> {
        panic!("Not implemented");
    }

}
