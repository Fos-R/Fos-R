use fosr::stage0;
use fosr::stage1;
use fosr::stage2;
use fosr::stage3;
#[cfg(feature = "net_injection")]
use fosr::stage4;
use fosr::structs::*;
use fosr::*;
mod cmd;

use std::collections::HashMap;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::Parser;
use crossbeam_channel::bounded;
use pnet::{datalink, ipnetwork::IpNetwork};

const CHANNEL_SIZE: usize = 500;

struct Profil {
    automata: stage2::tadam::AutomataLibrary,
    patterns: stage1::flowchronicle::PatternSet,
    config: config::Hosts,
}

impl Profil {
    fn load(profil: Option<&str>) -> Self {
        if let Some(path) = profil {
            Profil {
                automata: stage2::tadam::AutomataLibrary::from_dir(
                    Path::new(path)
                        .join("automata")
                        .to_str()
                        .expect("No \"automata\" directory found!"),
                ),
                config: config::import_config(
                    &fs::read_to_string(Path::new(path).join("profil.toml"))
                        .expect("Cannot access the configuration file."),
                ),
                patterns: stage1::flowchronicle::PatternSet::from_file(
                    Path::new(path).join("patterns").to_str().unwrap(),
                )
                .expect("Cannot load patterns"),
            }
        } else {
            log::info!("Load default profil");
            Profil {
                automata: stage2::tadam::AutomataLibrary::default(),
                config: config::Hosts::default(),
                patterns: stage1::flowchronicle::PatternSet::default(),
            }
        }
    }
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
        #[cfg(feature = "net_injection")]
        cmd::Command::Inject {
            taint,
            seed,
            profil,
            cpu_usage,
            outfile,
            flow_per_second,
            ..
        } => {
            let profil = Profil::load(profil.as_deref());
            log::debug!("Configuration: {:?}", profil.config);
            assert!(!local_interfaces.is_empty());
            for ip in local_interfaces.iter() {
                if let Some(s) = profil.config.get_name(ip) {
                    log::info!("Computer role: {s}");
                }
            }
            log::info!("Model initialization");
            let s0 = stage0::UniformGenerator::new_for_honeypot(
                seed,
                SystemTime::now().duration_since(UNIX_EPOCH).unwrap(),
                flow_per_second,
            );

            let automata_library = Arc::new(profil.automata);
            let patterns = Arc::new(profil.patterns);

            // let s1 = stage1::ConstantFlowGenerator::new(
            //     *local_interfaces.first().unwrap(),
            //     *local_interfaces.last().unwrap(),
            // ); // TODO: modify, only for testing
            // let s1 = stage1::ConfigBasedModifier::new(profil.config, s1);
            let s1 =
                stage1::flowchronicle::FCGenerator::new(patterns, profil.config.clone(), false);
            let s1 = stage1::FilterForOnline::new(local_interfaces.clone(), s1);
            let s2 = stage2::tadam::TadamGenerator::new(automata_library);
            let s3 = stage3::Stage3::new(taint, profil.config);
            let s4 = stage4::Stage4::new(taint, false);
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
            profil,
            outfile,
            flow_count,
            cpu_usage,
            minimum_threads,
            ..
        } => {
            let profil = Profil::load(profil.as_deref());
            let automata_library = Arc::new(profil.automata);
            let patterns = Arc::new(profil.patterns);

            if let Some(s) = seed {
                log::info!("Generating with seed {}", s);
            }
            log::info!("Model initialization");
            let s0 = stage0::UniformGenerator::new(seed, false, 2, flow_count);
            // let s1 = stage1::ConstantFlowGenerator::new(
            //     *local_interfaces.first().unwrap(),
            //     *local_interfaces.last().unwrap(),
            // ); // TODO: modify, only for testing
            let s1 =
                stage1::flowchronicle::FCGenerator::new(patterns, profil.config.clone(), false);
            let s2 = stage2::tadam::TadamGenerator::new(automata_library);
            let s3 = stage3::Stage3::new(false, profil.config);

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
        #[cfg(feature = "replay")]
        cmd::Command::Replay {
            file,
            config_path,
            taint,
            fast,
        } => {
            // Read content of the file
            log::debug!("Initialize stages");
            let mut flow_router_tx = HashMap::new();
            let mut stage_4_rx = HashMap::new();

            for proto in Protocol::iter() {
                let (tx, rx) = bounded::<Packets>(crate::CHANNEL_SIZE);
                flow_router_tx.insert(proto, tx);
                stage_4_rx.insert(proto, rx);
            }
            let ip_replacement_map: HashMap<Ipv4Addr, Ipv4Addr> = if let Some(path) = config_path {
                // read from config file
                replay::config::parse_config(
                    &fs::read_to_string(path).expect("Cannot access the configuration file."),
                )
            } else {
                // no IP replacement
                HashMap::new()
            };

            let stage_replay = replay::Replay::new(ip_replacement_map, file);
            let flows = stage_replay.parse_flows();

            // Flow router
            let thread_builder = thread::Builder::new().name("replay_flow_router".to_string());
            let flow_router = thread_builder
                .spawn(move || {
                    let mut sent_flows = 0;
                    for flow in flows {
                        let proto = flow.flow.get_proto();

                        let tx = flow_router_tx.get(&proto).expect("Unknown protocol");
                        stage3::send_online(&local_interfaces, flow, tx);
                        sent_flows += 1;
                    }

                    log::info!("Sent {} flows to be replayed", sent_flows);
                })
                .unwrap();

            // Stage 4
            let mut stage_4 = stage4::Stage4::new(taint, fast);
            let thread_builder = thread::Builder::new().name("replay_stage4".to_owned());
            let stage_4_thread = thread_builder
                .spawn(move || {
                    stage_4.start(stage_4_rx);
                })
                .unwrap();

            flow_router.join().unwrap();
            stage_4_thread.join().unwrap();
        }
    };
}

/// Runs the generation pipeline by launching each of the stages as separate threads.
///
/// The pipeline consists of multiple stages:
/// - Stage 0: Generates timing data using a uniform generator.
/// - Stage 1: Transforms stage 0 output into flow data based on flow patterns.
/// - Stage 2: Transforms flows into protocol-specific packet information using automata.
/// - Stage 3: Generates packets from flow data and forwards them to a collector (if applicable),
///   and optionally to stage 4 in online mode.
/// - Stage 4: (Optional) Further processes packets in online mode.
///
/// Additionally, the function sets up a thread for monitoring statistics and handling
/// control signals (Ctrl+C) to stop the generation threads.
///
/// # Parameters
///
/// - `local_interfaces`: A vector of local IPv4 interfaces. If empty, some stages may disable
///   certain functionality (e.g., network-specific processing).
/// - `outfile`: The optional output file path for exporting PCAP packets.
/// - `s0`: An implementation of the Stage 0 trait that produces the initial seed data.
/// - `s1`: An implementation of the Stage 1 trait that converts seed data to flow data.
/// - `s1_count`: The number of Stage 1 threads to launch.
/// - `s2`: An implementation of the Stage 2 trait that converts flows into protocol data.
/// - `s2_count`: The number of Stage 2 threads to launch.
/// - `s3`: The Stage3 instance that generates packets (for TCP, UDP, ICMP).
/// - `s3_count`: The number of Stage 3 threads per protocol.
/// - `cpu_usage`: A flag indicating if CPU usage statistics should be displayed in the monitoring UI.
/// - `s4`: An optional Stage4 instance for additional online processing.
///
/// # Behavior
///
/// This function creates and links multiple bounded channels between the stages:
/// - Between Stage 0 and Stage 1.
/// - Between Stage 1 and Stage 2.
/// - Between Stage 2 and Stage 3 (for each protocol).
/// - Between Stage 3 and the PCAP collector/exporter (if an output file is provided).
///
/// It then spawns threads for each stage along with a monitoring thread, waits for all generation
/// threads to finish, signals the UI thread to stop, and finally waits for the UI thread to exit.
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
