use crate::structs::*;

// Automaton are graphs. Graphs are not straightforward in Rust due to ownership, so we reference nodes by their index in the graph. Indices are never reused, leading to a small memory leak. Since we do not need to remove regularly nodes, it’s not a big deal.

struct TimedNode<T: Protocol> {
    out_edges: Vec<TimedEdge<T>>,
}

struct TimedEdge<T: Protocol> {
    dst_node: usize,
    src_node: usize, // not sure if useful
    transition_proba: f32,
    data: T,
    // expectation vector
    // covariance matrix
}

pub struct TimedAutomaton<T: Protocol> {
    graph: Vec<TimedNode<T>>
}

struct ConstraintsNode<T: Protocol> {
    out_edges: Vec<ConstraintsEdge<T>>,
}

struct ConstraintsEdge<T: Protocol> {
    data: T,
}

struct ConstraintsAutomaton<T: Protocol> {
    graph: Vec<ConstraintsNode<T>>
}

impl<T: Protocol> ConstraintsAutomaton<T> {
    fn new_packet_number_constraints_automaton(flow: &Flow) -> ConstraintsAutomaton<T> {
        panic!("Not implemented");
    }
}

impl ConstraintsAutomaton<TCPPacketInfo> {
    fn new_tcp_flags_constraints_automaton(flow: &Flow) -> ConstraintsAutomaton<TCPPacketInfo> {
        panic!("Not implemented");
    }
}

impl<T: Protocol> TimedAutomaton<T> {

    fn intersect_automata(&self, constraints: &ConstraintsAutomaton<T>) -> TimedAutomaton<T> {
        panic!("Not implemented");
    }

    fn sample(&self) -> PacketsIR<T> {
        panic!("Not implemented");
    }

}

impl TimedAutomaton<TCPPacketInfo> {
    fn import_timed_tcp_automaton(filename: &str) -> std::io::Result<Self> {
        panic!("Not implemented");
    }
}

