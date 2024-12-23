mod structs;
use crate::structs::*;

mod tcp;
mod udp;
mod icmp;

mod stage1;
mod stage2;
mod stage3;
mod stage4;

use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::thread;
use std::path::Path;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use crossbeam_channel::bounded;

const CHANNEL_SIZE: usize = 100;
const NB_STAGE1: usize = 1;
const NB_STAGE2: usize = 1;
const NB_STAGE3: usize = 1;
const NB_STAGE4: usize = 1;
// Stage 0 and pcap export have only one thread

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
        // TODO: API pour synchroniser les agents online
    },
    /// Offline mode: generate a pcap file
    Offline {
        #[arg(short, long, default_value="output.pcap", help="Output pcap file for synthetic network packets")] // TODO: remove default for release
        outfile: String,
        #[arg(short, long, default_value_t=false, help="Add noise in the output file")]
        noise: bool,
        #[arg(short='f', long, default_value_t=10, help="Minimum number of flows to generate.")] // TODO: use default value "1" for release
        nb_flows: i32,
        #[arg(short, long, default_value=None, help="Unix time for the beginning of the pcap. By default, use current time.")]
        start_unix_time: Option<u64>
    }
}

fn main() {
    let args = Args::parse();
    dbg!(&args);
    let (start_unix_time, nb_flows, online, noise) =
        match args.command {
            Command::Offline { start_unix_time, nb_flows, noise, .. } => (start_unix_time.map(|ts| Duration::from_secs(ts)), nb_flows, false, noise),
            Command::Online { } => (None, -1, true, false),
        };
    let start_unix_time = start_unix_time.unwrap_or(SystemTime::now().duration_since(UNIX_EPOCH).unwrap());

    let seed = match args.seed {
        Some(s) => s,
        None => 42, //rand::random(), TODO: change for release
    };
    println!("Generating with seed {}",seed);

    let mut threads = vec![];

    // All the channels
    let (tx_s0, rx_s1) = bounded::<Duration>(CHANNEL_SIZE);
    let (tx_s1, rx_s2) = bounded::<SeededData<Flow>>(CHANNEL_SIZE);
    let (tx_s2_tcp, rx_s3_tcp) = bounded::<SeededData<PacketsIR<tcp::TCPPacketInfo>>>(CHANNEL_SIZE);
    let (tx_s2_udp, _rx_s3_udp) = bounded::<SeededData<PacketsIR<udp::UDPPacketInfo>>>(CHANNEL_SIZE);
    let (tx_s2_icmp, _rx_s3_icmp) = bounded::<SeededData<PacketsIR<icmp::ICMPPacketInfo>>>(CHANNEL_SIZE);
    let (tx_s3, rx_s4) = bounded::<SeededData<Packets>>(CHANNEL_SIZE);
    let (tx_pcap, rx_pcap) = bounded::<Vec<Vec<u8>>>(CHANNEL_SIZE);

    let patterns = Arc::new(stage1::import_patterns("../models/mini_patterns.json").expect("Cannot load patterns"));

    // STAGE 0
    {
        let patterns = Arc::clone(&patterns);
        threads.push(thread::spawn(move || {
            let mut s0 = stage1::Stage0::new(seed, patterns, start_unix_time, nb_flows);
            // This part does not work for the moment so it’s commented
            loop {
                match s0.next() {
                    Some(ts) => { tx_s0.send(ts).unwrap(); },
                    None => { break; }
                };
            }
        }));
    }

    // STAGE 1

    for _ in 0..NB_STAGE1 {
        let rx_s1 = rx_s1.clone();
        let tx_s1 = tx_s1.clone();
        let patterns = Arc::clone(&patterns);
        threads.push(thread::spawn(move || {
            // Prepage stage 1 by loading the patterns
            let s1 = stage1::Stage1::new(seed, patterns);
            loop {
                match rx_s1.recv() {
                    Ok(ts) => {
                        let flows = s1.generate_flows(ts);
                        flows.into_iter().for_each(|f| tx_s1.send(f).unwrap());
                    },
                    Err(_) => { break; }
                }
            }
        }));
    }

    // STAGE 2

    let automata_library = Arc::new(stage2::import_automata_from_dir(Path::new(&args.models).join("tas").to_str().unwrap()));
    for _ in 0..NB_STAGE2 {
        let rx_s2 = rx_s2.clone();
        let tx_s2_tcp = tx_s2_tcp.clone();
        let tx_s2_udp = tx_s2_udp.clone();
        let tx_s2_icmp = tx_s2_icmp.clone();
        let automata_library = Arc::clone(&automata_library);
        threads.push(thread::spawn(move || {
            // Prepare stage 2 by loading the automata
            let mut s2 = stage2::Stage2::new(automata_library);

            loop {
                match rx_s2.recv() {
                    Ok(flow) => {
                        match flow.data {
                            Flow::TCPFlow(data) => {
                                tx_s2_tcp.send(s2.generate_tcp_packets_info(SeededData { seed : flow.seed, data })).unwrap();
                            }
                            Flow::UDPFlow(data) => {
                                tx_s2_udp.send(s2.generate_udp_packets_info(SeededData { seed : flow.seed, data })).unwrap();
                            },
                            Flow::ICMPFlow(data) => {
                                tx_s2_icmp.send(s2.generate_icmp_packets_info(SeededData { seed : flow.seed, data })).unwrap();
                            },
                        }
                    },
                    Err(_) => break
                }
            }
        }));
    }

    // STAGE 3

    for _ in 0..NB_STAGE3 {
        let rx_s3_tcp = rx_s3_tcp.clone();
        let tx_s3 = tx_s3.clone();
        let tx_pcap = tx_pcap.clone();
        threads.push(thread::spawn(move || {
            // Prepare stage 3 for TCP
            let s3 = stage3::Stage3::new(args.taint);
            loop {
                match rx_s3_tcp.recv() {
                    Ok(headers) => {
                        let flow_packets = s3.generate_tcp_packets(headers);
                        if online {
                            tx_s3.send(flow_packets).unwrap();
                        } else {
                            let mut noisy_flow = SeededData { seed: flow_packets.seed, data: flow_packets.data };
                            if noise { // insert noise
                                stage3::insert_noise(&mut noisy_flow);
                            }
                            tx_pcap.send(noisy_flow.data.packets).unwrap();
                        }
                    },
                    Err(_) => break
                }   
            }
        }));
    }

    // PCAP EXPORT

    if let Command::Offline { outfile, .. } = &args.command {
        let outfile = outfile.clone();
        threads.push(thread::spawn(move || {
            let mut packets_record = vec![];
            loop {
                match rx_pcap.recv() {
                    Ok(mut packets) => packets_record.append(&mut packets),
                    Err(_) => break,
                }
            }
            stage3::pcap_export(&packets_record, &outfile);
        }));
    }

    // STAGE 4 (online-mode only)

    if let Command::Online { .. } = args.command {
        for _ in 0..NB_STAGE4 {
            let rx_s4 = rx_s4.clone();
            threads.push(thread::spawn(move || {
                let s4 = stage4::Stage4::new();
                loop {
                    match rx_s4.recv() {
                        Ok(packets) => s4.send(packets),
                        Err(_) => break,
                    }
                }
            }));
        }
    }

    for thread in threads.into_iter() {
        thread.join().unwrap();
    }
}
