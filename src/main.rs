mod structs;
mod stage1;
mod stage2;
mod stage3;

fn main() {
    let mut s1 = stage1::Stage1::new();
    s1.import_patterns("pattern.txt");
    let mut s2 = stage2::Stage2::new();
    s2.import_automata("automata.dot");
    let s3 = stage3::Stage3::new();

    let flows = s1.generate_flows(100);
    let mut packets = vec![];
    for flow in flows.iter() {
        let headers = s2.generate_packets_info(&flow);
        packets.append(&mut s3.generate_tcp_packets(&headers));
    }
}
