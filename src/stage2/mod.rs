use crate::structs::*;
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

    pub fn import_automata(&mut self, filename: &str) {
        panic!("Not implemented");
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
