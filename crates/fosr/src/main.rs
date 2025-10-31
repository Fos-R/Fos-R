// we access the code through the library
use fosr::pcap2flow;
use fosr::stage0;
use fosr::stage1;
use fosr::stage2;
use fosr::stage3;
#[cfg(feature = "net_injection")]
use fosr::stage4;
use fosr::structs::*;
use fosr::ui::Target;
use fosr::*;
mod cmd; // cmd is not part of the library

use std::cmp::max;
use std::collections::HashMap;
use std::fs;
use std::fs::OpenOptions;
use std::io::BufWriter;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::time::Instant;

use clap::Parser;
use crossbeam_channel::bounded;
#[cfg(feature = "net_injection")]
use pnet::{datalink, ipnetwork::IpNetwork};
use pcap_file::pcap::{PcapPacket, PcapWriter};
use indicatif::HumanBytes;

const CHANNEL_SIZE: usize = 50;

struct Profile {
    automata: stage2::tadam::AutomataLibrary,
    patterns: stage1::flowchronicle::PatternSet,
    config: config::Hosts,
}

struct S4Param<T: stage4::NetEnabler> {
    net_enabler: T,
    injection_algo: cmd::InjectionAlgo,
}

impl Profile {
    fn load(profile: Option<&str>) -> Self {
        if let Some(path) = profile {
            Profile {
                automata: stage2::tadam::AutomataLibrary::from_dir(
                    Path::new(path)
                        .join("automata")
                        .to_str()
                        .expect("No \"automata\" directory found!"),
                ),
                config: config::import_config(
                    &fs::read_to_string(Path::new(path).join("profile.toml"))
                        .expect("Cannot access the configuration file."),
                ),
                patterns: stage1::flowchronicle::PatternSet::from_file(
                    Path::new(path)
                        .join("patterns/patterns.json")
                        .to_str()
                        .unwrap(),
                )
                .expect("Cannot load patterns"),
            }
        } else {
            log::info!("Load default profile");
            Profile {
                automata: stage2::tadam::AutomataLibrary::default(),
                config: config::Hosts::default(),
                patterns: stage1::flowchronicle::PatternSet::default(),
            }
        }
    }
}

/// The entry point of the application.
///
/// This function prepare the parameter for the function "run" according to the command line
fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = cmd::Args::parse();

    match args.command {
        cmd::Command::Pcap2Flow {
            input_pcap,
            output_csv,
            include_payloads,
        } => {
            let flows = pcap2flow::process_file(&input_pcap);
            pcap2flow::export_stats(&output_csv, flows, include_payloads);
        }
        #[cfg(feature = "net_injection")]
        cmd::Command::Inject {
            #[cfg(all(target_os = "linux", feature = "iptables"))]
            stealthy,
            seed,
            profile,
            outfile,
            order_pcap,
            flow_per_second,
            net_enabler,
            duration,
            deterministic,
            injection_algo,
        } => {
            #[cfg(not(all(target_os = "linux", feature = "iptables")))]
            let stealthy = false;

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
            // the local interfaces are used by the stage 4 and to identify local IPs
            // we do not include loopback interfaces or interfaces without an IPv4 address
            let local_interfaces: Vec<datalink::NetworkInterface> = datalink::interfaces()
                .into_iter()
                .filter(|iface| !iface.is_loopback() && iface.ips.iter().any(IpNetwork::is_ipv4))
                .collect();

            // for each interface, we extract its addresses
            let local_ips: Vec<Ipv4Addr> = local_interfaces
                .clone()
                .into_iter()
                .flat_map(extract_addr)
                .filter(|i| !i.is_loopback())
                .collect();
            log::debug!("IPv4 interfaces: {:?}", &local_ips);

            // identify the role of the current host
            let profile = Profile::load(profile.as_deref());
            log::debug!("Configuration: {:?}", profile.config);
            assert!(!local_ips.is_empty());
            let mut has_role = false;
            for ip in local_ips.iter() {
                if let Some(s) = profile.config.get_name(ip) {
                    log::info!("Computer role: {s}");
                }
                if profile.config.exists(ip) {
                    has_role = true;
                }
            }
            if !has_role {
                log::error!("This computer has no traffic to inject in this profile! Exiting.");
                process::exit(1);
            }

            // load the models
            let s0 = stage0::UniformGenerator::new_for_injection(
                seed,
                duration
                    .map(|d| humantime::parse_duration(&d).expect("Duration could not be parsed.")),
                flow_per_second,
                deterministic,
            );

            let automata_library = Arc::new(profile.automata);
            let patterns = Arc::new(profile.patterns);

            let s1 =
                stage1::flowchronicle::FCGenerator::new(patterns, profile.config.clone(), false);
            let s1 = stage1::FilterForOnline::new(local_ips.clone(), s1);
            let s2 = stage2::tadam::TadamGenerator::new(automata_library);
            let s3 = stage3::Stage3::new(!stealthy, profile.config);

            // run
            log::info!("Network enabler: {net_enabler:?}");
            match net_enabler {
                #[cfg(all(any(target_os = "windows", target_os = "linux"), feature = "ebpf"))]
                cmd::NetEnabler::Ebpf => {
                    let s4net = S4Param {
                        net_enabler: stage4::ebpf::EBPFNetEnabler::new(false, &local_interfaces),
                        injection_algo,
                    };
                    run(
                        local_ips,
                        outfile.map(|o| ExportParams {
                            outfile: o,
                            order_pcap,
                        }),
                        s0,
                        (s1, 1),
                        (s2, 1),
                        (s3, 1),
                        Arc::new(ui::Stats::default()),
                        Some(s4net),
                    );
                }
                #[cfg(all(target_os = "linux", feature = "iptables"))]
                cmd::NetEnabler::Iptables => {
                    let s4net = S4Param {
                        net_enabler: stage4::iptables::IPTablesNetEnabler::new(!stealthy, false),
                        injection_algo,
                    };
                    run(
                        local_ips,
                        outfile.map(|o| ExportParams {
                            outfile: o,
                            order_pcap,
                        }),
                        s0,
                        (s1, 1),
                        (s2, 1),
                        (s3, 1),
                        Arc::new(ui::Stats::default()),
                        Some(s4net),
                    );
                }
            };
        }
        cmd::Command::CreatePcap {
            seed,
            profile,
            outfile,
            packets_count,
            monothread,
            order_pcap,
            start_time,
            duration,
            taint,
        } => {
            // load the models
            let profile = Profile::load(profile.as_deref());
            let automata_library = Arc::new(profile.automata);
            let patterns = Arc::new(profile.patterns);
            // handle the parameters: either there is a packet count target or a duration
            let (target, duration) = match (packets_count, duration) {
                (None, Some(d)) => {
                    let d = humantime::parse_duration(&d).expect("Duration could not be parsed.");
                    log::info!("Generating a pcap of {d:?}");
                    (Target::Duration(d), Some(d))
                }
                (Some(p), None) => {
                    log::info!("Generation at least {p} packets");
                    (Target::PacketCount(p), None)
                }
                _ => unreachable!(),
            };
            if let Some(s) = seed {
                log::info!("Generating with seed {s}");
            }
            let initial_ts: Duration = if let Some(start_time) = start_time {
                // try to parse a date
                if let Ok(d) = humantime::parse_rfc3339_weak(&start_time) {
                    d.duration_since(UNIX_EPOCH).unwrap()
                } else if let Ok(n) = start_time.parse::<u64>() {
                    Duration::from_secs(n)
                } else {
                    panic!("Could not parse start time");
                }
            } else {
                SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
            };

            let s0 = stage0::UniformGenerator::new(seed, false, 2, initial_ts, duration);
            let s1 =
                stage1::flowchronicle::FCGenerator::new(patterns, profile.config.clone(), false);
            let s2 = stage2::tadam::TadamGenerator::new(automata_library);
            let s3 = stage3::Stage3::new(taint, profile.config);

            let cpu_count = num_cpus::get();
            let (s1_count, s2_count, s3_count) = (
                max(1, cpu_count / 2),
                max(1, cpu_count / 2),
                max(1, cpu_count / 2),
            ); // the total is indeed larger than cpu_count. This has been empirically assessed to be a correct heuristic to maximise the performances

            if monothread {
                log::info!("Monothread generation");
                run_monothread(
                    ExportParams {
                        outfile,
                        order_pcap,
                    },
                    s0,
                    s1,
                    s2,
                    s3,
                );
            } else {
                run(
                    vec![],
                    Some(ExportParams {
                        outfile,
                        order_pcap,
                    }),
                    s0,
                    (s1, s1_count),
                    (s2, s2_count),
                    (s3, s3_count),
                    Arc::new(ui::Stats::new(target)),
                    None::<S4Param<stage4::DummyNetEnabler>>,
                );
            }
        }
        cmd::Command::Untaint { input, output } => {
            pcap2flow::untaint_file(&input, &output);
        } // #[cfg(feature = "replay")]
          // cmd::Command::Replay {
          //     file,
          //     // config_path,
          //     taint,
          //     fast,
          // } => {
          //     // Read content of the file
          //     log::debug!("Initialize stages");
          //     let mut flow_router_tx = HashMap::new();
          //     let mut stage_4_rx = HashMap::new();

          //     for proto in Protocol::iter() {
          //         let (tx, rx) = bounded::<Packets>(crate::CHANNEL_SIZE);
          //         flow_router_tx.insert(proto, tx);
          //         stage_4_rx.insert(proto, rx);
          //     }
          //     // let ip_replacement_map: HashMap<Ipv4Addr, Ipv4Addr> = if let Some(path) = config_path {
          //     //     // read from config file
          //     //     replay::parse_config(
          //     //         &fs::read_to_string(path).expect("Cannot access the configuration file."),
          //     //     )
          //     // } else {
          //     //     // no IP replacement
          //     //     HashMap::new()
          //     // };

          //     let stage_replay = replay::Replay::new();
          //     let flows = stage_replay.parse_flows(&file);

          //     // Flow router
          //     let thread_builder = thread::Builder::new().name("replay_flow_router".to_string());
          //     let flow_router = thread_builder
          //         .spawn(move || {
          //             let mut sent_flows = 0;
          //             for flow in flows {
          //                 let proto = flow.flow.get_proto();

          //                 let tx = flow_router_tx.get(&proto).expect("Unknown protocol");
          //                 stage3::send_online(&local_interfaces, flow, tx);
          //                 sent_flows += 1;
          //             }

          //             log::info!("Sent {} flows to be replayed", sent_flows);
          //         })
          //         .unwrap();

          //     // Stage 4
          //     let mut stage_4 = stage4::Stage4::new(taint, fast);
          //     let thread_builder = thread::Builder::new().name("replay_stage4".to_owned());
          //     let stage_4_thread = thread_builder
          //         .spawn(move || {
          //             stage_4.start(stage_4_rx);
          //         })
          //         .unwrap();

          //     flow_router.join().unwrap();
          //     stage_4_thread.join().unwrap();
          // }
    };
}

struct ExportParams {
    /// the output file path
    outfile: String,
    /// whether to order the pcap once the generation has ended
    order_pcap: bool,
}

/// Runs the generation pipeline by launching each of the stages as separate threads.
///
/// The pipeline consists of multiple stages:
/// - Stage 0: Generates timing data using a uniform generator.
/// - Stage 1: Transforms stage 0 output into flow data based on flow patterns.
/// - Stage 2: Transforms flows into protocol-specific packet information using automata.
/// - Stage 3: Generates packets from flow data.
/// - Stage 4: (Optional) Send and receive packets with raw sockets.
///
/// # Parameters
///
/// - `local_interfaces`: local IPv4 interfaces
/// - `export`: optional structure with parameters for the pcap export
/// - `s0`: a stage 0 implementation
/// - `s1`: a stage 1 implementation
/// - `s2`: a stage 2 implementation
/// - `s3`: a stage 3 implementation
/// - `stats`: an Arc to a structure containing generation statistics
/// - `s4net`: an optional network enable
#[allow(clippy::too_many_arguments)]
fn run<T: stage4::NetEnabler>(
    local_interfaces: Vec<Ipv4Addr>,
    export: Option<ExportParams>,
    s0: impl stage0::Stage0,
    s1: (impl stage1::Stage1, usize),
    s2: (impl stage2::Stage2, usize),
    s3: (stage3::Stage3, usize),
    stats: Arc<ui::Stats>,
    s4net: Option<S4Param<T>>,
) {
    let (s1, s1_count) = s1;
    let (s2, s2_count) = s2;
    let (s3, s3_count) = s3;

    let mut threads = vec![];
    let mut gen_threads = vec![];
    let mut export_threads = vec![];

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
        let (tx_s3_to_pcap, rx_pcap) = thingbuf::mpsc::blocking::with_recycle::<
            Packets,
            PacketsRecycler,
        >(CHANNEL_SIZE, PacketsRecycler {});

        // Handle ctrl+C
        let stats_ctrlc = Arc::clone(&stats);
        let do_export = export.is_some();
        ctrlc::set_handler(move || {
            if !stats_ctrlc.should_stop() && do_export {
                log::warn!("Exporting the generated data, please wait a few seconds");
                stats_ctrlc.stop_early();
            } else {
                process::exit(1);
            }
        })
        .expect("Error setting Ctrl-C handler");

        // STAGE 0
        let builder = thread::Builder::new().name("Stage0".into());
        let stats_s0 = Arc::clone(&stats);
        gen_threads.push(
            builder
                .spawn(move || {
                    let _ = stage0::run_channel(s0, tx_s0, stats_s0);
                })
                .unwrap(),
        );

        // STAGE 1

        for _ in 0..s1_count {
            let rx_s1 = rx_s1.clone();
            let tx_s1 = tx_s1.clone();
            let s1 = s1.clone();
            let stats = Arc::clone(&stats);
            let builder = thread::Builder::new().name("Stage1".into());
            gen_threads.push(
                builder
                    .spawn(move || {
                        let _ = stage1::run_channel(s1, rx_s1, tx_s1, stats);
                    })
                    .unwrap(),
            );
        }

        // STAGE 2

        for _ in 0..s2_count {
            let rx_s2 = rx_s2.clone();
            let tx_s2 = tx_s2.clone();
            let s2 = s2.clone();
            let stats = Arc::clone(&stats);
            let builder = thread::Builder::new().name("Stage2".into());
            gen_threads.push(
                builder
                    .spawn(move || {
                        let _ = stage2::run_channel(s2, rx_s2, tx_s2, stats);
                    })
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
                let tx_s3_to_pcap = tx_s3_to_pcap.clone();
                let s3 = s3.clone();
                let stats = Arc::clone(&stats);
                let local_interfaces = local_interfaces.clone();

                let builder = thread::Builder::new().name(format!("Stage3-{proto:?}"));
                match proto {
                    Protocol::TCP => {
                        let rx_s3_tcp = rx_s3_tcp.clone();
                        gen_threads.push(
                            builder
                                .spawn(move || {
                                    let _ = stage3::run_channel(
                                        |f, p, a| s3.generate_tcp_packets(f, p, a),
                                        local_interfaces,
                                        rx_s3_tcp,
                                        tx,
                                        tx_s3_to_pcap,
                                        stats,
                                        do_export,
                                    );
                                })
                                .unwrap(),
                        );
                    }
                    Protocol::UDP => {
                        let rx_s3_udp = rx_s3_udp.clone();
                        gen_threads.push(
                            builder
                                .spawn(move || {
                                    let _ = stage3::run_channel(
                                        |f, p, a| s3.generate_udp_packets(f, p, a),
                                        local_interfaces,
                                        rx_s3_udp,
                                        tx,
                                        tx_s3_to_pcap,
                                        stats,
                                        do_export,
                                    );
                                })
                                .unwrap(),
                        );
                    }
                    Protocol::ICMP => {
                        let rx_s3_icmp = rx_s3_icmp.clone();
                        gen_threads.push(
                            builder
                                .spawn(move || {
                                    let _ = stage3::run_channel(
                                        |f, p, a| s3.generate_icmp_packets(f, p, a),
                                        local_interfaces,
                                        rx_s3_icmp,
                                        tx,
                                        tx_s3_to_pcap,
                                        stats,
                                        do_export,
                                    );
                                })
                                .unwrap(),
                        );
                    }
                }
            }
        }

        // PCAP EXPORT

        let builder = thread::Builder::new().name("Pcap-export".into());
        export_threads.push(if let Some(export) = export {
            builder
                .spawn(move || {
                    stage3::run_export(rx_pcap, export.outfile, export.order_pcap);
                })
                .unwrap()
        } else {
            // if there is no export, we still need to consume the packets
            builder
                .spawn(move || {
                    stage3::run_dummy_export(rx_pcap);
                })
                .unwrap()
        });

        // STAGE 4 (injection mode only)
        #[cfg(feature = "net_injection")]
        if let Some(s4net) = s4net {
            let stats = Arc::clone(&stats);
            let builder = thread::Builder::new().name("Stage4".into());
            gen_threads.push(
                builder
                    .spawn(move || match s4net.injection_algo {
                        cmd::InjectionAlgo::Fast => {
                            stage4::start_fast(s4net.net_enabler, rx_s4, stats)
                        }
                        cmd::InjectionAlgo::Reliable => {
                            stage4::start_reliable(s4net.net_enabler, rx_s4, stats)
                        }
                    })
                    .unwrap(),
            );
        }
    }

    {
        let stats = Arc::clone(&stats);
        let builder = thread::Builder::new().name("Monitoring".into());
        threads.push(builder.spawn(move || ui::run(stats)).unwrap());
    }

    // Wait for the generation threads to end
    for thread in gen_threads {
        thread.join().unwrap();
    }

    if !export_threads.is_empty() {
        // log::info!("Generation complete: exporting");
        for thread in export_threads {
            thread.join().unwrap();
        }
    }

    // stop all remaining threads
    stats.stop_early();

    // Wait for the other threads to stop
    for thread in threads {
        thread.join().unwrap();
    }
}

/// Run the generation with only one thread
fn run_monothread(
    export: ExportParams,
    s0: impl stage0::Stage0,
    s1: impl stage1::Stage1,
    s2: impl stage2::Stage2,
    s3: stage3::Stage3,
) {
    let start = Instant::now();

    log::info!("Stage 0 generation");
    let vec = stage0::run_vec(s0);
    log::info!("Stage 1 generation");
    let vec = stage1::run_vec(s1, vec);
    log::info!("Stage 2 generation");
    let vec = stage2::run_vec(s2, vec);

    let mut all_packets = vec![];

    log::info!("Stage 3 generation");
    all_packets.append(&mut stage3::run_vec(
        |f, p, a| s3.generate_udp_packets(f, p, a),
        vec.udp,
    ));
    all_packets.append(&mut stage3::run_vec(
        |f, p, a| s3.generate_tcp_packets(f, p, a),
        vec.tcp,
    ));
    all_packets.append(&mut stage3::run_vec(
        |f, p, a| s3.generate_icmp_packets(f, p, a),
        vec.icmp,
    ));

    let gen_duration = start.elapsed().as_secs_f64();
    let total_size = all_packets.iter().map(|p| p.data.len()).sum::<usize>() as u64;
    log::info!("Generation throughput: {}/s", HumanBytes(((total_size as f64) / gen_duration) as u64));

    if export.order_pcap {
        log::info!("Sorting the packets");
        all_packets.sort_unstable();
    }

    let file_out = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&export.outfile)
        .expect("Error opening or creating file");
    let mut pcap_writer = PcapWriter::new(BufWriter::new(file_out)).expect("Error writing file");

    log::info!("Pcap export");
    for packet in all_packets.iter() {
        pcap_writer
            .write_packet(&PcapPacket::new(
                packet.timestamp,
                packet.data.len() as u32,
                &packet.data,
            ))
            .unwrap();
    }
}
