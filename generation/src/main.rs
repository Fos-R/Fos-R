mod structs;
use structs::*;

mod tcp;
mod udp;
mod icmp;
use crate::tcp::*;
use crate::udp::*;
use crate::icmp::*;

mod stage1;
mod stage2;
mod stage3;
mod stage4;

use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::mpsc::channel;
use std::thread;
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
    #[arg(short='f', long, default_value_t=10, help="Minimum number of flows to generate. -1 for no limit.")] // TODO: use default value "1" for release
    nb_flows: isize,
    #[arg(short, long, default_value="../models/test", help="Path to models directory")] // TODO: make required and remove default for release
    models_path: String,
}

fn main() {
    let args = Args::parse();

    let pcap_export = args.outfile.is_some();
    let mut nb_flows = args.nb_flows;
    let seed = match args.seed {
        Some(s) => s,
        None => 42, //rand::random(), TODO: change for release
    };
    println!("Generating with seed {}",seed);

    let mut threads = vec![];

    // All the channels
    let (tx_s1, rx_s2) = channel::<Option<SeededData<Flow>>>();
    let (tx_s2_tcp, rx_s3_tcp) = channel::<Option<SeededData<PacketsIR<TCPPacketInfo>>>>();
    let (tx_s2_udp, rx_s3_udp) = channel::<Option<SeededData<PacketsIR<UDPPacketInfo>>>>();
    let (tx_s2_icmp, rx_s3_icmp) = channel::<Option<SeededData<PacketsIR<ICMPPacketInfo>>>>();
    let (tx_s3, rx_s4) = channel::<Option<SeededData<Packets>>>();
    let (tx_pcap, rx_pcap) = channel::<Option<Vec<Vec<u8>>>>();

    // STAGE 1

    threads.push(thread::spawn(move || {
        // Prepage stage 1 by loading the patterns
        let s1 = stage1::Stage1::new(seed);
        // This part does not work for the moment so it’s commented
        // s1.import_patterns("../models/patterns.json").expect("Cannot load patterns");

        // Stage 1: only one instance
        while nb_flows > 0 {
            let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
            let flows = s1.generate_flows(ts);
            nb_flows -= flows.len() as isize;
            flows.into_iter().for_each(|f| tx_s1.send(Some(f)).unwrap());
        }
        tx_s1.send(None).unwrap();
    }));

    // STAGE 2

    threads.push(thread::spawn(move || {
        // Prepare stage 2 by loading the automata
        let mut s2 = stage2::Stage2::new();
        let nb_automata = s2.import_automata_from_dir(Path::new(&args.models_path).join("tas").to_str().unwrap()); // TODO: don’t copy the automata for all stage2’s instances
        assert!(nb_automata > 0);

        loop {
            match rx_s2.recv().unwrap() {
                Some(flow) => {
                    match flow.data {
                        Flow::TCPFlow(data) => {
                            tx_s2_tcp.send(Some(s2.generate_tcp_packets_info(SeededData { seed : flow.seed, data }))).unwrap();
                        }
                        Flow::UDPFlow(data) => {
                            tx_s2_udp.send(Some(s2.generate_udp_packets_info(SeededData { seed : flow.seed, data }))).unwrap();
                        },
                        Flow::ICMPFlow(data) => {
                            tx_s2_icmp.send(Some(s2.generate_icmp_packets_info(SeededData { seed : flow.seed, data }))).unwrap();
                        },
                    }
                },
                None => break
            }
        }
        tx_s2_tcp.send(None).unwrap();
        tx_s2_udp.send(None).unwrap();
        tx_s2_icmp.send(None).unwrap();
    }));

    // STAGE 3

    threads.push(thread::spawn(move || {
        // Prepare stage 3 for TCP
        let s3 = stage3::Stage3::new(args.taint);
        loop {
            match rx_s3_tcp.recv().unwrap() {
                Some(headers) => {
                    let flow_packets = s3.generate_tcp_packets(headers);
                    if pcap_export {
                        let mut noisy_flow = SeededData { seed: flow_packets.seed, data: flow_packets.data.clone() };
                        if args.noise { // insert noise
                            stage3::insert_noise(&mut noisy_flow);
                        }
                        tx_pcap.send(Some(noisy_flow.data.packets)).unwrap();
                    }
                    if args.send {
                        tx_s3.send(Some(flow_packets)).unwrap();
                    }
                },
                None => break
            }
            tx_s3.send(None).unwrap();
            tx_pcap.send(None).unwrap();
        }
    }));

    // PCAP EXPORT

    if let Some(outfile) = args.outfile {
        threads.push(thread::spawn(move || {
            let mut packets_record = vec![];
            loop {
                match rx_pcap.recv().unwrap() {
                    Some(mut packets) => packets_record.append(&mut packets),
                    None => break,
                }
            }
            stage3::pcap_export(&packets_record, &outfile);
        }));
    }

    // STAGE 4

    else if args.send {
        threads.push(thread::spawn(move || {
            let s4 = stage4::Stage4::new();
            loop {
                match rx_s4.recv().unwrap() {
                    Some(packets) => s4.send(packets),
                    None => break,
                }
            }
        }));
    }

    for thread in threads.into_iter() {
        thread.join().unwrap();
    }
}
