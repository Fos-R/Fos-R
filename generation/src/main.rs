mod structs;
use structs::*;
mod tcp;
mod udp;
mod icmp;

mod stage1;
mod stage2;
mod stage3;
mod stage4;

use std::time::{Duration, SystemTime, UNIX_EPOCH};
use clap::{Parser};
use std::path::Path;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value=Some("output.pcap"), help="Output file for synthetic network packets")] // TODO: remove default for release
    outfile: Option<String>,
    #[arg(short, long, default_value_t=false, help="Add noise in the output file", requires="outfile")]
    noise: bool,
    #[arg(short, long, default_value_t=false, help="Taint the packets to easily identify them")]
    taint: bool,
    #[arg(short, long, default_value_t=false, help="Send packets through the network interfaces")]
    send: bool,
    #[arg(short='S', long, default_value=None, help="Seed for random number generation")] // TODO: remove default value for release
    seed: Option<u64>,
    #[arg(short='p', long, default_value_t=100, help="Mininum number of packets to generate. -1 for no limit.")] // TODO: use default value "1" for release
    nb_packets: isize,
    #[arg(short='f', long, default_value_t=10, help="Minimum number of flows to generate. -1 for no limit.")] // TODO: use default value "1" for release
    nb_flows: isize,
    #[arg(short, long, default_value="../models/test", help="Path to models directory")] // TODO: make required and remove default for release
    models_path: String,
}

fn main() {
    let args = Args::parse();

    let mut nb_flows = args.nb_flows;
    let mut nb_packets = args.nb_packets;
    let seed = match args.seed {
        Some(s) => s,
        None => 42, //rand::random(), TODO: change for release
    };
    println!("Generating with seed {}",seed);

    // Prepage stage 1 by loading the patterns
    // This part does not work for the moment so it’s commented
    // let mut s1 = stage1::Stage1::new(seed);
    // s1.import_patterns("../models/patterns.json").expect("Cannot load patterns");

    // Prepare stage 2 by loading the automata
    let mut s2 = stage2::Stage2::new(seed);
    let nb_automata = s2.import_automata_from_dir(Path::new(&args.models_path).join("tas").to_str().unwrap());
    assert!(nb_automata > 0);

    // Prepare stage 3
    let s3 = stage3::Stage3::new(seed, args.taint);
    let optional_s4 = if args.send { Some(stage4::Stage4::new()) } else { None };

    // A dummy starting time
    let mut ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let mut packets = vec![];
    while args.nb_packets > 0 && args.nb_flows > 0 {
        let headers = s2.generate_tcp_packets_info_no_flow(21, ts);
        let new_packets = &mut s3.generate_tcp_packets(&headers);
        // TODO: add noise with another function (only for packets saved to a pcap file)
        if let Some(s4) = &optional_s4 {
            s4.send(&headers.flow, &new_packets)
        }
        packets.append(new_packets);
        ts += Duration::from_millis(1000); // TODO
        if nb_flows > 0 {
            nb_flows -= 1;
        }
        if nb_packets > 0 {
            nb_packets -= new_packets.len() as isize;
        }
    }
    // export packets to pcap file
    if let Some(outfile) = args.outfile {
        s3.pcap_export(&outfile);
    }
}
