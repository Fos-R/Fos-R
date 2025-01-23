mod structs;
use crate::structs::*;
mod cmd;
mod ui;

mod icmp;
mod tcp;
mod udp;

mod stage0;
mod stage1;
use stage1::flowchronicle;
mod stage2;
use stage2::tadam;
mod replay;
mod stage3;
mod stage4;

use std::collections::HashMap;
use std::env;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use clap::Parser;
use crossbeam_channel::bounded;
use pnet::{datalink, ipnetwork::IpNetwork};

// monitor threads with "top -H -p $(pgrep fosr)"
const CHANNEL_SIZE: usize = 500;

fn main() {
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "info"); // default log level: info
    }
    env_logger::init();
    let args = cmd::Args::parse();
    log::debug!("{:?}", &args);

    // Extract all IPv4 local interfaces (except loopback)
    let extract_addr = |iface: datalink::NetworkInterface| {
        iface
            .ips
            .into_iter()
            .filter(IpNetwork::is_ipv4)
            .map(|i| match i {
                IpNetwork::V4(data) => data.ip(),
                _ => panic!("Impossible"),
            })
    };
    let local_interfaces: Vec<Ipv4Addr> = datalink::interfaces()
        .into_iter()
        .flat_map(extract_addr)
        .filter(|i| !i.is_loopback())
        .collect();
    log::debug!("IPv4 interfaces: {:?}", &local_interfaces);

    match args.command {
        cmd::Command::Replay { infile, .. } => replay::replay(&infile),
        cmd::Command::Honeynet { taint, models, cpu_usage, .. } => {
            assert!(!local_interfaces.is_empty());
            let models = models.unwrap_or("../models/test".to_string()); // remove
            log::info!("Model initialization");
            // TODO: modify seed initialization
            let s0 = stage0::UniformGenerator::new(Some(0), true, 2, 100);
            let s1 = stage1::ConstantFlowGenerator::new(
                *local_interfaces.first().unwrap(),
                *local_interfaces.last().unwrap(),
            ); // TODO: modify, only for testing
            let automata_library = Arc::new(tadam::AutomataLibrary::from_dir(
                Path::new(&models).join("tas").to_str().unwrap(),
            ));
            let s2 = tadam::TadamGenerator::new(automata_library);
            let s3 = stage3::Stage3::new(taint);
            // TODO: allow outfile
            run(local_interfaces, None, s0, s1, 3, s2, 1, s3, 1, cpu_usage);
        }
        cmd::Command::CreatePcap {
            seed,
            models,
            outfile,
            flow_count,
            cpu_usage,
            ..
        } => {
            let models = models.unwrap_or("../models/test".to_string()); // remove
            if let Some(s) = seed {
                log::trace!("Generating with seed {}", s);
            }
            log::info!("Model initialization");
            let s0 = stage0::UniformGenerator::new(seed, false, 2, flow_count);
            // TODO utiliser include_bytes à la place
            let s1 = stage1::ConstantFlowGenerator::new(
                *local_interfaces.first().unwrap(),
                *local_interfaces.last().unwrap(),
            ); // TODO: modify, only for testing
               // let patterns = Arc::new(flowchronicle::PatternSet::from_file(Path::new(&models).join("patterns.json").to_str().unwrap()).expect("Cannot load patterns"));
               // let s1 = flowchronicle::FCGenerator::new(patterns, false);
            let automata_library = Arc::new(tadam::AutomataLibrary::from_dir(
                Path::new(&models).join("tas").to_str().unwrap(),
            ));
            let s2 = tadam::TadamGenerator::new(automata_library);
            let s3 = stage3::Stage3::new(false);

            run(vec![], Some(outfile), s0, s1, 3, s2, 3, s3, 6, cpu_usage);
        }
    };
}

fn run(
    local_interfaces: Vec<Ipv4Addr>,
    outfile: Option<String>,
    s0: impl stage0::Stage0,
    s1: impl stage1::Stage1,
    s1_count: u8,
    s2: impl stage2::Stage2,
    s2_count: u8,
    s3: stage3::Stage3,
    s3_count: u8,
    cpu_usage: bool,
) {
    let stats = Arc::new(ui::Stats::default());
    let running = Arc::new(AtomicBool::new(true));

    let mut threads = vec![];
    let mut gen_threads = vec![];

    // block to automatically drop channels before the joins
    {
        // Channels creation
        let (tx_s0, rx_s1) = bounded::<SeededData<Duration>>(CHANNEL_SIZE);
        let (tx_s1, rx_s2) = bounded::<SeededData<Flow>>(CHANNEL_SIZE);
        let (tx_s2_tcp, rx_s3_tcp) =
            bounded::<SeededData<PacketsIR<tcp::TCPPacketInfo>>>(CHANNEL_SIZE);
        let (tx_s2_udp, rx_s3_udp) =
            bounded::<SeededData<PacketsIR<udp::UDPPacketInfo>>>(CHANNEL_SIZE);
        let (tx_s2_icmp, rx_s3_icmp) =
            bounded::<SeededData<PacketsIR<icmp::ICMPPacketInfo>>>(CHANNEL_SIZE);
        let tx_s2 = stage2::S2Sender {
            tcp: tx_s2_tcp,
            udp: tx_s2_udp,
            icmp: tx_s2_icmp,
        };
        let mut tx_s3 = HashMap::new();
        let mut rx_s4 = HashMap::new();
        for proto in Protocol::iter() {
            let mut tx_s3_hm = HashMap::new();
            for iface in &local_interfaces {
                let (tx, rx) = bounded::<SeededData<Packets>>(CHANNEL_SIZE);
                tx_s3_hm.insert(*iface, tx);
                rx_s4.insert((*iface, proto), rx);
            }
            tx_s3.insert(proto, tx_s3_hm);
        }
        let (tx_s3_to_collector, rx_collector) = bounded::<Packets>(CHANNEL_SIZE);
        let (tx_collector, rx_pcap) = bounded::<Vec<Packet>>(CHANNEL_SIZE);

        // STAGE 0

        let builder = thread::Builder::new().name("Stage0".into());
        gen_threads.push(builder.spawn(move || stage0::run(s0, tx_s0)).unwrap());

        // STAGE 1

        for _ in 0..s1_count {
            let rx_s1 = rx_s1.clone();
            let tx_s1 = tx_s1.clone();
            let s1 = s1.clone();
            let local_interfaces = local_interfaces.clone();
            let builder = thread::Builder::new().name("Stage1".into());
            gen_threads.push(
                builder
                    .spawn(move || {
                        stage1::run(s1, rx_s1, tx_s1, local_interfaces);
                    })
                    .unwrap(),
            );
        }

        // STAGE 2

        for _ in 0..s2_count {
            let rx_s2 = rx_s2.clone();
            let tx_s2 = tx_s2.clone();
            let s2 = s2.clone();
            let builder = thread::Builder::new().name("Stage2".into());
            gen_threads.push(
                builder
                    .spawn(move || stage2::run(s2, rx_s2, tx_s2))
                    .unwrap(),
            );
        }

        // STAGE 3

        for (proto, tx_s3_hm) in tx_s3 {
            for _ in 0..s3_count {
                let tx_s3_hm = tx_s3_hm.clone();
                let tx_s3_to_collector = tx_s3_to_collector.clone();
                let s3 = s3.clone();
                let stats = Arc::clone(&stats);

                let builder = thread::Builder::new().name(format!("Stage3-{:?}", proto));
                let online = !local_interfaces.is_empty();
                match proto {
                    Protocol::TCP => {
                        let rx_s3_tcp = rx_s3_tcp.clone();
                        gen_threads.push(
                            builder
                                .spawn(move || {
                                    stage3::run(
                                        |f| s3.generate_tcp_packets(f),
                                        rx_s3_tcp,
                                        tx_s3_hm,
                                        tx_s3_to_collector,
                                        stats,
                                        online,
                                    )
                                })
                                .unwrap(),
                        );
                    }
                    Protocol::UDP => {
                        let rx_s3_udp = rx_s3_udp.clone();
                        gen_threads.push(
                            builder
                                .spawn(move || {
                                    stage3::run(
                                        |f| s3.generate_udp_packets(f),
                                        rx_s3_udp,
                                        tx_s3_hm,
                                        tx_s3_to_collector,
                                        stats,
                                        online,
                                    )
                                })
                                .unwrap(),
                        );
                    }
                    Protocol::ICMP => {
                        let rx_s3_icmp = rx_s3_icmp.clone();
                        gen_threads.push(
                            builder
                                .spawn(move || {
                                    stage3::run(
                                        |f| s3.generate_icmp_packets(f),
                                        rx_s3_icmp,
                                        tx_s3_hm,
                                        tx_s3_to_collector,
                                        stats,
                                        online,
                                    )
                                })
                                .unwrap(),
                        );
                    }
                }
            }
        }

        // PCAP EXPORT

        if let Some(actual_outfile) = outfile {
            let builder = thread::Builder::new().name("Pcap-collector".into());
            gen_threads.push(
                builder
                    .spawn(move || stage3::run_collector(rx_collector, tx_collector))
                    .unwrap(),
            );

            let builder = thread::Builder::new().name("Pcap-export".into());
            gen_threads.push(
                builder
                    .spawn(move || stage3::run_export(rx_pcap, &actual_outfile))
                    .unwrap(),
            );
        }

        // STAGE 4 (online mode only)

        if !local_interfaces.is_empty() {
            for ((iface, proto), rx) in rx_s4 {
                // let rx = rx.clone();
                let builder = thread::Builder::new().name(format!("Stage4-{:?}-{iface}", proto));
                gen_threads.push(
                    builder
                        .spawn(move || {
                            log::trace!("Start S4");
                            let s4 = stage4::Stage4::new(iface, proto);
                            while let Ok(packets) = rx.recv() {
                                s4.send(packets)
                            }
                            log::trace!("S4 stops");
                        })
                        .unwrap(),
                );
            }
        }
    }

    {
        let stats = Arc::clone(&stats);
        let running = Arc::clone(&running);
        let builder = thread::Builder::new().name("Monitoring".into());
        threads.push(builder.spawn(move || ui::run(stats, running, cpu_usage)).unwrap());
    }

    // Wait for the generation threads to end
    for thread in gen_threads {
        thread.join().unwrap();
    }
    // Tell the other threads to stop
    running.store(false, Ordering::Relaxed);
    // Wait for the other threads to stop
    for thread in threads {
        thread.join().unwrap();
    }
}
