mod structs;
use structs::*;
mod tcp;
mod udp;
mod icmp;

mod stage1;
mod stage2;
mod stage3;

use std::time::{Duration, SystemTime, UNIX_EPOCH};
use clap::{Parser};
use std::path::Path;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    // The default values are just here to test conveniently but won’t be present in the final version
    #[arg(short, long, default_value=Some("output.pcap"), help="Output file for synthetic network packets")]
    outfile: Option<String>,
    #[arg(short, long, help="Network interface to send synthetic network packets")]
    interface: Option<String>,
    #[arg(short, long, default_value_t=10, help="Number of flows to generate")]
    nb_flows: i32,
    #[arg(short, long, default_value=Some("../models/test"), help="Path to models directory")]
    models_path: String,
}

fn main() {
    let args = Args::parse();

    // Prepage stage 1 by loading the patterns
    // This part does not work for the moment so it’s commented
    // let mut s1 = stage1::Stage1::new(42);
    // s1.import_patterns("../models/patterns.json").expect("Cannot load patterns");

    // Prepare stage 2 by loading the automata
    let mut s2 = stage2::Stage2::new(42);
    let nb_automata = s2.import_automata_from_dir(Path::new(&args.models_path).join("tas").to_str().unwrap());
    assert!(nb_automata > 0);

    // Prepare stage 3
    let s3 = stage3::Stage3::new(42);

    // A dummy starting time
    let mut ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let mut packets = vec![];
    for _ in 0..args.nb_flows { // Generate 10 flows
        let headers = s2.generate_tcp_packets_info_no_flow(21, ts);
        packets.append(&mut s3.generate_tcp_packets(&headers).unwrap());
        ts += Duration::from_millis(1000);
    }
    // export packets to pcap file
    println!("TODO: export packets to {:?}", args.outfile);
}
