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
use clap::{Parser, Subcommand};
use std::path::Path;
use std::sync::{Arc, Mutex};

#[derive(Debug, Parser, Clone)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[clap(subcommand)]
    command: Command,

    #[arg(short, long, global=true, default_value_t=false, help="Taint the packets to easily identify them")]
    taint: bool,
    #[arg(short, long, global=true, help="Seed for random number generation")]
    seed: Option<u64>,
    #[arg(short, long, global=true, default_value="../models/test", help="Path to models directory")] // TODO: make required and remove default for release
    models: String,

}

#[derive(Debug, Subcommand, Clone)]
enum Command {
    /// Online mode: send packets through the network interfaces
    Online {
    },
    /// Offline mode: generate a pcap file
    Offline {
        #[arg(short, long, default_value="output.pcap", help="Output pcap file for synthetic network packets")] // TODO: remove default for release
        outfile: String,
        #[arg(short, long, default_value_t=false, help="Add noise in the output file")]
        noise: bool,
        #[arg(short='f', long, default_value_t=10, help="Minimum number of flows to generate.")] // TODO: use default value "1" for release
        nb_flows: isize,
    }
}

fn main() {
    let args = Args::parse();
    dbg!(&args);
    let (nb_flows, online, noise) =
        match args.command {
            Command::Offline { nb_flows, noise, .. } => (nb_flows, false, noise),
            Command::Online { } => (-1, true, false),
        };
    let nb_flows = Arc::new(Mutex::new(nb_flows));

    let seed = match args.seed {
        Some(s) => s,
        None => 42, //rand::random(), TODO: change for release
    };
    println!("Generating with seed {}",seed);

    let mut threads = vec![];

    // All the channels
    let (tx_s1, rx_s2) = channel::<Option<SeededData<Flow>>>();
    let (tx_s2_tcp, rx_s3_tcp) = channel::<Option<SeededData<PacketsIR<TCPPacketInfo>>>>();
    let (tx_s2_udp, _rx_s3_udp) = channel::<Option<SeededData<PacketsIR<UDPPacketInfo>>>>();
    let (tx_s2_icmp, _rx_s3_icmp) = channel::<Option<SeededData<PacketsIR<ICMPPacketInfo>>>>();
    let (tx_s3, rx_s4) = channel::<Option<SeededData<Packets>>>();
    let (tx_pcap, rx_pcap) = channel::<Option<Vec<Vec<u8>>>>();

    // STAGE 1

    let patterns = Arc::new(stage1::import_patterns("../models/mini_patterns.json").expect("Cannot load patterns"));
    {
        let nb_flows = Arc::clone(&nb_flows);
        threads.push(thread::spawn(move || {
            // Prepage stage 1 by loading the patterns
            let s1 = stage1::Stage1::new(seed, patterns.clone());
            // This part does not work for the moment so it’s commented

            loop {
                let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
                let flows = s1.generate_flows(ts);
                if !online { // when online, just continue as much as needed
                    let mut counter = nb_flows.lock().unwrap();
                    if *counter < 0 { break; }
                    *counter -= flows.len() as isize;
                }
                flows.into_iter().for_each(|f| tx_s1.send(Some(f)).unwrap());
            }
            tx_s1.send(None).unwrap();
        }));
    }

    // STAGE 2

    let automata_library = Arc::new(stage2::import_automata_from_dir(Path::new(&args.models).join("tas").to_str().unwrap()));
    {
        threads.push(thread::spawn(move || {
            // Prepare stage 2 by loading the automata
            let mut s2 = stage2::Stage2::new(automata_library.clone());

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
    }

    // STAGE 3

    {
        threads.push(thread::spawn(move || {
            // Prepare stage 3 for TCP
            let s3 = stage3::Stage3::new(args.taint);
            loop {
                match rx_s3_tcp.recv().unwrap() {
                    Some(headers) => {
                        let flow_packets = s3.generate_tcp_packets(headers);
                        if online {
                            tx_s3.send(Some(flow_packets)).unwrap();
                        } else {
                            let mut noisy_flow = SeededData { seed: flow_packets.seed, data: flow_packets.data.clone() };
                            if noise { // insert noise
                                stage3::insert_noise(&mut noisy_flow);
                            }
                            tx_pcap.send(Some(noisy_flow.data.packets)).unwrap();
                        }
                    },
                    None => break
                }
                tx_s3.send(None).unwrap();
                tx_pcap.send(None).unwrap();
            }
        }));
    }

    // PCAP EXPORT

    if let Command::Offline { outfile, .. } = &args.command {
        let outfile = outfile.clone();
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

    // STAGE 4 (online-mode only)

    if let Command::Online { .. } = args.command {
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
