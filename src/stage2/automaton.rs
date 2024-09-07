use crate::structs;

// Automaton are graphs. Graphs are not straightforward in Rust due to ownership, so we reference nodes by their index in the graph. Indices are never reused, leading to a small memory leak. Since we do not need to remove regularly nodes, it’s not a big deal.

struct TimedNode<T: structs::Protocol> {
    edges: Vec<TimedEdge<T>>,
}

struct TimedEdge<T: structs::Protocol> {
    dst_node: usize,
    src_node: usize, // not sure if useful
    transition_proba: f32,
    data: T,
    // expectation vector
    // covariance matrix
}

pub struct TimedAutomaton<T: structs::Protocol> {
    graph: Vec<TimedNode<T>>
}

struct ConstraintsNode<T: structs::Protocol> {
    edges: Vec<ConstraintsEdge<T>>,
}

struct ConstraintsEdge<T: structs::Protocol> {
    data: T,
}

struct ConstraintsAutomaton<T: structs::Protocol> {
    graph: Vec<ConstraintsNode<T>>
}

impl<T: structs::Protocol> ConstraintsAutomaton<T> {
    fn new_packet_number_constraints_automaton(flow: &structs::Flow) -> ConstraintsAutomaton<T> {
        panic!("Not implemented");
    }
}

impl ConstraintsAutomaton<structs::TCPPacketInfo> {
    fn new_tcp_flags_constraints_automaton(flow: &structs::Flow) -> ConstraintsAutomaton<structs::TCPPacketInfo> {
        panic!("Not implemented");
    }
}

impl<T: structs::Protocol> TimedAutomaton<T> {

    fn intersect_automata(&self, constraints: &ConstraintsAutomaton<T>) -> TimedAutomaton<T> {
        panic!("Not implemented");
    }

    fn sample(&self) -> structs::PacketsIR<T> {
        panic!("Not implemented");
    }

}

impl TimedAutomaton<structs::TCPPacketInfo> {
    fn import_timed_tcp_automaton(filename: &str) -> std::io::Result<Self> {
        panic!("Not implemented");
    }
}

