use fosr::stage0;
use fosr::stage1;
use fosr::stage2;
use fosr::stage3;
#[cfg(feature = "net_injection")]
use fosr::stage4;
use fosr::structs::*;
use fosr::ui::Target;
use fosr::*;
mod cmd;

use std::collections::HashMap;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::Parser;
use crossbeam_channel::bounded;
use pnet::{datalink, ipnetwork::IpNetwork};

const CHANNEL_SIZE: usize = 50;

struct Profile {
    automata: stage2::tadam::AutomataLibrary,
    patterns: stage1::flowchronicle::PatternSet,
    config: config::Hosts,
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

#[cfg(feature = "ebpf_log")]
#[tokio::main]
async fn main() {
    start();
}

#[cfg(not(feature = "ebpf_log"))]
fn main() {
    start();
}

/// The entry point of the application.
///
/// This function performs the following steps:
/// 1. Initializes logging and parses command-line arguments.
/// 2. Extracts all non-loopback IPv4 local interface addresses.
/// 3. Depending on the parsed subcommand, it loads configuration, pattern files,
///    automata libraries, and initializes several stages of the generator pipeline.
/// 4. Invokes the `run` function with appropriate parameters to start the generation
///    process either in injection mode or in pcap creation mode.
fn start() {
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
    let local_interfaces: Vec<datalink::NetworkInterface> = datalink::interfaces()
        .into_iter()
        .filter(|iface| !iface.is_loopback())
        .collect();
    let local_ips: Vec<Ipv4Addr> = local_interfaces
        .clone()
        .into_iter()
        .flat_map(extract_addr)
        .filter(|i| !i.is_loopback())
        .collect();
    log::debug!("IPv4 interfaces: {:?}", &local_ips);

    match args.command {
        #[cfg(feature = "net_injection")]
        cmd::Command::Inject {
            taint,
            seed,
            profile,
            cpu_usage,
            outfile,
            flow_per_second,
            ..
        } => {
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
            log::info!("Model initialization");
            let s0 = stage0::UniformGenerator::new_for_honeypot(
                seed,
                SystemTime::now().duration_since(UNIX_EPOCH).unwrap(),
                flow_per_second,
            );

            let automata_library = Arc::new(profile.automata);
            let patterns = Arc::new(profile.patterns);

            let s1 =
                stage1::flowchronicle::FCGenerator::new(patterns, profile.config.clone(), false);
            let s1 = stage1::FilterForOnline::new(local_ips.clone(), s1);
            let s2 = stage2::tadam::TadamGenerator::new(automata_library);
            let s3 = stage3::Stage3::new(taint, profile.config);
            let s4 = stage4::Stage4::new(taint, false, &local_interfaces);
            run(
                local_ips,
                outfile,
                s0,
                (s1, 3),
                (s2, 1),
                (s3, 1),
                cpu_usage,
                false,
                Arc::new(ui::Stats::default()),
                Some(s4),
            );
        }
        cmd::Command::CreatePcap {
            seed,
            profile,
            outfile,
            packets_count,
            cpu_usage,
            minimum_threads,
            order_pcap,
            start_time,
            duration,
        } => {
            let profile = Profile::load(profile.as_deref());
            let automata_library = Arc::new(profile.automata);
            let patterns = Arc::new(profile.patterns);
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
            log::info!("Model initialization");
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
            let s3 = stage3::Stage3::new(false, profile.config);

            let cpu_count = num_cpus::get();
            let (s1_count, s2_count, s3_count) = if minimum_threads {
                (1, 1, 1)
            } else {
                (cpu_count/2, cpu_count/2, cpu_count/2)
            };
            run(
                vec![],
                Some(outfile),
                s0,
                (s1, s1_count),
                (s2, s2_count),
                (s3, s3_count),
                cpu_usage,
                order_pcap,
                Arc::new(ui::Stats::new(target)),
                None,
            );
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
/// - `local_interfaces`: A vector of local IPv4 interfaces. If empty, some stages may disable
///   certain functionality (e.g., network-specific processing).
/// - `outfile`: The optional output file path for exporting PCAP packets.
/// - `s0`: An implementation of the Stage 0 trait that produces the initial seed data.
/// - `s1`: An implementation of the Stage 1 trait that converts seed data to flow data.
/// - `s2`: An implementation of the Stage 2 trait that converts flows into protocol data.
/// - `s3`: The Stage3 instance that generates packets (for TCP, UDP, ICMP).
/// - `cpu_usage`: A flag indicating if CPU usage statistics should be displayed in the monitoring UI.
/// - `s4`: An optional Stage4 instance for additional online processing.
fn run(
    local_interfaces: Vec<Ipv4Addr>,
    outfile: Option<String>,
    s0: impl stage0::Stage0,
    s1: (impl stage1::Stage1, usize),
    s2: (impl stage2::Stage2, usize),
    s3: (stage3::Stage3, usize),
    cpu_usage: bool,
    order_pcap: bool,
    stats: Arc<ui::Stats>,
    s4: Option<stage4::Stage4>,
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
        let export = outfile.is_some();
        ctrlc::set_handler(move || {
            if !stats_ctrlc.should_stop() && export {
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
                    let _ = stage0::run(s0, tx_s0, stats_s0);
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
                        let _ = stage1::run(s1, rx_s1, tx_s1, stats);
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
                        let _ = stage2::run(s2, rx_s2, tx_s2, stats);
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
                let pcap_export = outfile.is_some();
                match proto {
                    Protocol::TCP => {
                        let rx_s3_tcp = rx_s3_tcp.clone();
                        gen_threads.push(
                            builder
                                .spawn(move || {
                                    let _ = stage3::run(
                                        |f, p, a| s3.generate_tcp_packets(f, p, a),
                                        local_interfaces,
                                        rx_s3_tcp,
                                        tx,
                                        tx_s3_to_pcap,
                                        stats,
                                        pcap_export,
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
                                    let _ = stage3::run(
                                        |f, p, a| s3.generate_udp_packets(f, p, a),
                                        local_interfaces,
                                        rx_s3_udp,
                                        tx,
                                        tx_s3_to_pcap,
                                        stats,
                                        pcap_export,
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
                                    let _ = stage3::run(
                                        |f, p, a| s3.generate_icmp_packets(f, p, a),
                                        local_interfaces,
                                        rx_s3_icmp,
                                        tx,
                                        tx_s3_to_pcap,
                                        stats,
                                        pcap_export,
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
        export_threads.push(
            builder
                .spawn(move || {
                    stage3::run_export(rx_pcap, outfile, order_pcap);
                })
                .unwrap(),
        );

        // STAGE 4 (online mode only)
        // TODO: only one stage 4 for all protocols

        #[cfg(any(feature = "replay", feature = "net_injection"))]
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
        let builder = thread::Builder::new().name("Monitoring".into());
        threads.push(builder.spawn(move || ui::run(stats, cpu_usage)).unwrap());
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
