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

struct TimedAutomaton<T: structs::Protocol> {
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

fn create_constraints_automaton<T: structs::Protocol>(flow: structs::Flow) -> ConstraintsAutomaton<T> {
    panic!("Not implemented");
}

fn intersect_automata<T: structs::Protocol>(automaton: TimedAutomaton<T>, constraints: ConstraintsAutomaton<T>) -> TimedAutomaton<T> {
    panic!("Not implemented");
}

fn import_timed_TCP_automaton(filename: &str) -> std::io::Result<TimedAutomaton<structs::TCPPacketInfo>> {
    panic!("Not implemented");
}

fn sample<T: structs::Protocol>(automaton: TimedAutomaton<T>) -> structs::PacketsIR<T> {
    panic!("Not implemented");
}

