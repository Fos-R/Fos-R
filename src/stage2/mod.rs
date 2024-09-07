use crate::structs;
mod automaton;

pub struct Stage2 {
    tcp_automata: Vec<automaton::TimedAutomaton<structs::TCPPacketInfo>>,
    udp_automata: Vec<automaton::TimedAutomaton<structs::UDPPacketInfo>>,
    icmp_automata: Vec<automaton::TimedAutomaton<structs::ICMPPacketInfo>>
}

impl Stage2 {

    pub fn new() -> Self {
        Stage2 { tcp_automata: vec![], udp_automata: vec![], icmp_automata: vec![] }
    }

    pub fn import_automata(&mut self, filename: &str) {
        panic!("Not implemented");
    }

    pub fn generate_packets_info<T: structs::Protocol>(&self, flow: &structs::Flow) -> structs::PacketsIR<T> {
        panic!("Not implemented");
    }

}
