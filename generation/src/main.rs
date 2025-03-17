use fosr::stage0;
use fosr::stage1;
use fosr::stage2;
use fosr::stage3;
use fosr::stage4;
use fosr::structs::*;
use fosr::*;
mod cmd;

use std::collections::HashMap;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::Parser;
use crossbeam_channel::bounded;
use pnet::{datalink, ipnetwork::IpNetwork};

const CHANNEL_SIZE: usize = 500;

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = cmd::Args::parse();

    // Extract all IPv4 local interfaces (except loopback)
    let extract_addr = |iface: datalink::NetworkInterface| {
        iface
            .ips
            .into_iter()
            .filter(IpNetwork::is_ipv4)
            .map(|i| match i {
                IpNetwork::V4(data) => data.ip(),
                _ => unreachable!(),
            })
    };
    let local_interfaces: Vec<Ipv4Addr> = datalink::interfaces()
        .into_iter()
        .flat_map(extract_addr)
        .filter(|i| !i.is_loopback())
        .collect();
    log::debug!("IPv4 interfaces: {:?}", &local_interfaces);

    match args.command {
        // cmd::Command::Replay { infile, .. } => replay::replay(&infile),
        cmd::Command::Honeynet {
            taint,
            seed,
            automata,
            patterns,
            config_path,
            cpu_usage,
            outfile,
            flow_per_second,
            ..
        } => {
            let config_str =
                &fs::read_to_string(config_path).expect("Cannot access the configuration file.");
            let hosts = config::import_config(config_str);
            log::debug!("Configuration: {:?}", hosts);
            assert!(!local_interfaces.is_empty());
            for ip in local_interfaces.iter() {
                if let Some(s) = hosts.get_name(ip) {
                    log::info!("Computer role: {s}");
                }
            }
            log::info!("Model initialization");
            let s0 = stage0::UniformGenerator::new_for_honeypot(
                seed,
                SystemTime::now().duration_since(UNIX_EPOCH).unwrap(),
                flow_per_second,
            );
            let patterns = match &patterns {
                Some(patterns) => stage1::flowchronicle::PatternSet::from_file(
                    Path::new(patterns).to_str().unwrap(),
                )
                .expect("Cannot load patterns"),
                None => {
                    log::info!("Load default patterns");
                    stage1::flowchronicle::PatternSet::default()
                }
            };
            let patterns = Arc::new(patterns);

            // let s1 = stage1::ConstantFlowGenerator::new(
            //     *local_interfaces.first().unwrap(),
            //     *local_interfaces.last().unwrap(),
            // ); // TODO: modify, only for testing
            // let s1 = stage1::ConfigBasedModifier::new(hosts, s1);
            let s1 = stage1::flowchronicle::FCGenerator::new(patterns, hosts.clone(), false);
            let s1 = stage1::FilterForOnline::new(local_interfaces.clone(), s1);
            let automata_library = match &automata {
                Some(automata) => {
                    stage2::tadam::AutomataLibrary::from_dir(Path::new(automata).to_str().unwrap())
                }
                None => {
                    log::info!("Load default automata");
                    stage2::tadam::AutomataLibrary::default()
                }
            };
            let automata_library = Arc::new(automata_library);
            let s2 = stage2::tadam::TadamGenerator::new(automata_library);
            let s3 = stage3::Stage3::new(taint, hosts);
            let s4 = stage4::Stage4::new(taint);
            run(
                local_interfaces,
                outfile,
                s0,
                s1,
                3,
                s2,
                1,
                s3,
                1,
                cpu_usage,
                Some(s4),
            );
        }
        cmd::Command::CreatePcap {
            seed,
            automata,
            patterns,
            outfile,
            flow_count,
            cpu_usage,
            config_path,
            minimum_threads,
            ..
        } => {
            let config_str =
                &fs::read_to_string(config_path).expect("Cannot access the configuration file.");
            let hosts = config::import_config(config_str);

            let automata_library = match &automata {
                Some(automata) => {
                    stage2::tadam::AutomataLibrary::from_dir(Path::new(automata).to_str().unwrap())
                }
                None => stage2::tadam::AutomataLibrary::default(),
            };
            let automata_library = Arc::new(automata_library);

            let patterns = match &patterns {
                Some(patterns) => stage1::flowchronicle::PatternSet::from_file(
                    Path::new(patterns).to_str().unwrap(),
                )
                .expect("Cannot load patterns"),
                None => stage1::flowchronicle::PatternSet::default(),
            };
            let patterns = Arc::new(patterns);

            if let Some(s) = seed {
                log::info!("Generating with seed {}", s);
            }
            log::info!("Model initialization");
            let s0 = stage0::UniformGenerator::new(seed, false, 2, flow_count);
            // let s1 = stage1::ConstantFlowGenerator::new(
            //     *local_interfaces.first().unwrap(),
            //     *local_interfaces.last().unwrap(),
            // ); // TODO: modify, only for testing
            let s1 = stage1::flowchronicle::FCGenerator::new(patterns, hosts.clone(), false);
            let s2 = stage2::tadam::TadamGenerator::new(automata_library);
            let s3 = stage3::Stage3::new(false, hosts);

            if minimum_threads {
                run(
                    vec![],
                    Some(outfile),
                    s0,
                    s1,
                    1,
                    s2,
                    1,
                    s3,
                    1,
                    cpu_usage,
                    None,
                );
            } else {
                run(
                    vec![],
                    Some(outfile),
                    s0,
                    s1,
                    3,
                    s2,
                    3,
                    s3,
                    6,
                    cpu_usage,
                    None,
                );
            }
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
    s4: Option<stage4::Stage4>,
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
        let (tx_s2_tcp, rx_s3_tcp) = bounded::<SeededData<PacketsIR<TCPPacketInfo>>>(CHANNEL_SIZE);
        let (tx_s2_udp, rx_s3_udp) = bounded::<SeededData<PacketsIR<UDPPacketInfo>>>(CHANNEL_SIZE);
        let (tx_s2_icmp, rx_s3_icmp) =
            bounded::<SeededData<PacketsIR<ICMPPacketInfo>>>(CHANNEL_SIZE);
        let tx_s2 = stage2::S2Sender {
            tcp: tx_s2_tcp,
            udp: tx_s2_udp,
            icmp: tx_s2_icmp,
        };
        // TODO: only create if online
        let mut tx_s3 = HashMap::new();
        let mut rx_s4 = HashMap::new();
        for proto in Protocol::iter() {
            let (tx, rx) = bounded::<Packets>(CHANNEL_SIZE);
            rx_s4.insert(proto, rx);
            tx_s3.insert(proto, tx);
        }
        // TODO: only create if offline
        let (tx_s3_to_collector, rx_collector) = bounded::<Packets>(CHANNEL_SIZE);
        // TODO: mettre un channel_size = 1 ici ?
        let (tx_collector, rx_pcap) = bounded::<Vec<Packet>>(CHANNEL_SIZE);

        // STAGE 0
        // Handle ctrl+C
        let s0_running = Arc::new(AtomicBool::new(true));
        let r = s0_running.clone();
        ctrlc::set_handler(move || {
            if r.load(Ordering::Relaxed) {
                log::warn!("Ending the generation, please wait a few seconds");
                r.store(false, Ordering::Relaxed);
            } else {
                log::warn!("Ending immediately");
                process::abort();
            }
        })
        .expect("Error setting Ctrl-C handler");

        let builder = thread::Builder::new().name("Stage0".into());
        gen_threads.push(
            builder
                .spawn(move || stage0::run(s0, tx_s0, s0_running))
                .unwrap(),
        );

        // STAGE 1

        for _ in 0..s1_count {
            let rx_s1 = rx_s1.clone();
            let tx_s1 = tx_s1.clone();
            let s1 = s1.clone();
            let builder = thread::Builder::new().name("Stage1".into());
            gen_threads.push(
                builder
                    .spawn(move || {
                        stage1::run(s1, rx_s1, tx_s1);
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

        for (proto, tx) in tx_s3 {
            for _ in 0..s3_count {
                let tx = if local_interfaces.is_empty() {
                    None
                } else {
                    Some(tx.clone())
                };
                let tx_s3_to_collector = tx_s3_to_collector.clone();
                let s3 = s3.clone();
                let stats = Arc::clone(&stats);
                let local_interfaces = local_interfaces.clone();

                let builder = thread::Builder::new().name(format!("Stage3-{:?}", proto));
                let pcap_export = outfile.is_some();
                match proto {
                    Protocol::TCP => {
                        let rx_s3_tcp = rx_s3_tcp.clone();
                        gen_threads.push(
                            builder
                                .spawn(move || {
                                    stage3::run(
                                        |f| s3.generate_tcp_packets(f),
                                        local_interfaces,
                                        rx_s3_tcp,
                                        tx,
                                        tx_s3_to_collector,
                                        stats,
                                        pcap_export,
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
                                        local_interfaces,
                                        rx_s3_udp,
                                        tx,
                                        tx_s3_to_collector,
                                        stats,
                                        pcap_export,
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
                                        local_interfaces,
                                        rx_s3_icmp,
                                        tx,
                                        tx_s3_to_collector,
                                        stats,
                                        pcap_export,
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
        // TODO: only one stage 4 for all protocols

        if let Some(mut s4) = s4 {
            let builder = thread::Builder::new().name("Stage4".into());
            gen_threads.push(
                builder
                    .spawn(move || {
                        s4.start(rx_s4);
                    })
                    .unwrap(),
            );
        }
    }

    {
        let stats = Arc::clone(&stats);
        let running = Arc::clone(&running);
        let builder = thread::Builder::new().name("Monitoring".into());
        threads.push(
            builder
                .spawn(move || ui::run(stats, running, cpu_usage))
                .unwrap(),
        );
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
