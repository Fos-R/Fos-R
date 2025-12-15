use fosr_lib::export;
#[cfg(feature = "net_injection")]
use fosr_lib::inject;
use fosr_lib::models;
use fosr_lib::stage0;
use fosr_lib::stage1;
use fosr_lib::stage2;
use fosr_lib::stage3;
use fosr_lib::stats;
use fosr_lib::utils;
use fosr_lib::*;
mod cmd;

use std::cmp::max;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::BufWriter;
use std::net::Ipv4Addr;
use std::process;
use std::sync::Arc;
use std::thread;
use std::time::Instant;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::DateTime;
use chrono::Offset;
use chrono::TimeZone;
use chrono_tz::Tz;
use clap::Parser;
use crossbeam_channel::bounded;
use indicatif::HumanBytes;
use itertools::kmerge;
use pcap_file::pcap::{PcapPacket, PcapWriter};
#[cfg(feature = "net_injection")]
use pnet::{datalink, ipnetwork::IpNetwork};
use std::sync::mpsc::channel;

const CHANNEL_SIZE: usize = 50;

// Use Jemalloc when possible
#[cfg(all(target_os = "linux", any(target_env = "", target_env = "gnu")))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

struct InjectParam<T: inject::NetEnabler> {
    #[allow(unused)]
    net_enabler: T,
    #[allow(unused)]
    injection_algo: cmd::InjectionAlgo,
}

/// The entry point of the application.
///
/// This function prepare the parameter for the function "run" according to the command line
fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = cmd::Args::parse();

    match args.command {
        cmd::Command::CreatePcap {
            seed,
            outfile,
            packets_count,
            profile,
            no_order_pcap,
            start_time,
            duration,
            flow_per_day,
            tz,
            jobs,
            config,
            taint,
            default_models,
            custom_models,
        } => {
            // load the models
            let source = if let Some(custom_models) = custom_models {
                models::ModelsSource::UserDefined(custom_models)
            } else {
                default_models.get_source()
            };

            let mut model = models::Models::from_source(source).unwrap();
            if let Some(config) = config {
                model = model.with_config(&config).unwrap();
            }
            let automata_library = Arc::new(model.automata);
            // let patterns = Arc::new(model.patterns);
            let bn = Arc::new(model.bn);
            // handle the parameters: either there is a packet count target or a duration
            let (target, duration) = match (packets_count, duration) {
                (None, Some(d)) => {
                    let d = humantime::parse_duration(&d).expect("Duration could not be parsed.");
                    log::info!("Generating a pcap of {d:?}");
                    (stats::Target::GenerationDuration(d), Some(d))
                }
                (Some(p), None) => {
                    log::info!("Generation at least {p} packets");
                    (stats::Target::PacketCount(p), None)
                }
                _ => unreachable!(),
            };
            if let Some(s) = seed {
                log::info!("Generating with seed {s}");
            }

            let (mut initial_ts, ts_requires_offset): (Duration, bool) =
                if let Some(start_time) = start_time {
                    // try to parse a date
                    if let Ok(d) = humantime::parse_rfc3339_weak(&start_time) {
                        (d.duration_since(UNIX_EPOCH).unwrap(), true)
                    } else if let Ok(n) = start_time.parse::<u64>() {
                        (Duration::from_secs(n), false)
                    } else {
                        panic!("Could not parse start time");
                    }
                } else {
                    (SystemTime::now().duration_since(UNIX_EPOCH).unwrap(), false)
                };

            let tz_offset = match tz {
                Some(tz_str) => {
                    let tz: Tz = tz_str.parse().expect("Could not parse the timezone");
                    let date = DateTime::from_timestamp(initial_ts.as_secs() as i64, 0)
                        .unwrap()
                        .naive_utc();
                    let tz = tz.offset_from_utc_datetime(&date).fix();
                    log::info!("Using {tz_str} timezone (UTC{tz})");
                    tz
                }
                None => {
                    let date = DateTime::from_timestamp(initial_ts.as_secs() as i64, 0)
                        .unwrap()
                        .naive_utc();
                    let tz = chrono::Local::now()
                        .timezone()
                        .offset_from_local_datetime(&date)
                        .single()
                        .expect("Ambiguous local date from timestamp")
                        .fix();
                    log::info!("Using local timezone (UTC{tz})");
                    tz
                }
            };

            // the initial timestamp was computed assuming that the timezone is UTC.
            // now, compute the actual timestamp taking into account the timezone
            if ts_requires_offset {
                initial_ts = Duration::from_secs(
                    DateTime::from_timestamp(initial_ts.as_secs() as i64, 0)
                        .unwrap()
                        .naive_utc()
                        .and_local_timezone(tz_offset)
                        .unwrap()
                        .timestamp() as u64,
                );
            }

            let s0 = stage0::BinBasedGenerator::new(
                seed,
                false,
                flow_per_day,
                model.time_bins,
                initial_ts,
                duration,
                tz_offset,
            );
            let s1 = stage1::bayesian_networks::BNGenerator::new(bn, false);
            // let s1 = stage1::flowchronicle::FCGenerator::new(patterns, model.config.clone(), false);
            let s2 = stage2::tadam::TadamGenerator::new(automata_library);
            let s3 = stage3::Stage3::new(taint); //, model.config);
            let jobs = jobs.unwrap_or(max(1, num_cpus::get() / 2));
            match profile {
                cmd::GenerationProfile::Fast => {
                    run_fast(
                        ExportParams {
                            outfile,
                            order_pcap: !no_order_pcap,
                        },
                        s0,
                        s1,
                        s2,
                        s3,
                        jobs,
                    );
                    // }
                }
                cmd::GenerationProfile::Efficient => {
                    let (s1_count, s2_count, s3_count) = (
                        max(1, jobs / 3),
                        max(1, jobs / 3),
                        max(1, jobs - (2 * jobs) / 3),
                    );
                    // the total is indeed larger than cpu_count. This has been empirically assessed to be a correct heuristic to maximise the performances

                    run_efficient(
                        vec![],
                        Some(ExportParams {
                            outfile,
                            order_pcap: !no_order_pcap,
                        }),
                        s0,
                        (s1, s1_count),
                        (s2, s2_count),
                        (s3, s3_count),
                        Arc::new(stats::Stats::new(target)),
                        None::<InjectParam<inject::DummyNetEnabler>>,
                    );
                }
            }
        }
        cmd::Command::Untaint { input, output } => {
            utils::untaint_file(&input, &output);
        }
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
fn run_efficient<T: inject::NetEnabler>(
    local_interfaces: Vec<Ipv4Addr>,
    export: Option<ExportParams>,
    s0: impl stage0::Stage0,
    s1: (impl stage1::Stage1, usize),
    s2: (impl stage2::Stage2, usize),
    s3: (stage3::Stage3, usize),
    stats: Arc<stats::Stats>,
    #[allow(unused)] s4net: Option<InjectParam<T>>,
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
        let (tx_s0, rx_s1) = bounded::<SeededData<TimePoint>>(CHANNEL_SIZE);
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
                                        |f, p, v, a| s3.generate_tcp_packets(f, p, v, a),
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
                                        |f, p, v, a| s3.generate_udp_packets(f, p, v, a),
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
                                        |f, p, v, a| s3.generate_icmp_packets(f, p, v, a),
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
                    export::run_export(rx_pcap, export.outfile, export.order_pcap);
                })
                .unwrap()
        } else {
            // if there is no export, we still need to consume the packets
            builder
                .spawn(move || {
                    export::run_dummy_export(rx_pcap);
                })
                .unwrap()
        });

        // STAGE 4 (injection mode only)
        #[cfg(feature = "net_injection")]
        if let Some(s4net) = s4net {
            let stats = Arc::clone(&stats);
            let builder = thread::Builder::new().name("inject".into());
            gen_threads.push(
                builder
                    .spawn(move || match s4net.injection_algo {
                        cmd::InjectionAlgo::Fast => {
                            inject::start_fast(s4net.net_enabler, rx_s4, stats)
                        }
                        cmd::InjectionAlgo::Reliable => {
                            inject::start_reliable(s4net.net_enabler, rx_s4, stats)
                        }
                    })
                    .unwrap(),
            );
        }
    }

    {
        let stats = Arc::clone(&stats);
        let builder = thread::Builder::new().name("Monitoring".into());
        threads.push(
            builder
                .spawn(move || stats::show_progression(stats))
                .unwrap(),
        );
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

/// Run the generation with very little contention, but the generated dataset must fit in RAM
fn run_fast(
    export: ExportParams,
    s0: impl stage0::Stage0,
    s1: impl stage1::Stage1,
    s2: impl stage2::Stage2,
    s3: stage3::Stage3,
    jobs: usize,
) {
    // TODO: remettre "stats", ctrlc, etc.
    let start = Instant::now();

    let vec = stage0::run_vec(s0);
    if vec.is_empty() {
        log::error!("No generated data: duration is too small");
    } else {
        let chunk_size = (((vec.len() as f64) / (jobs as f64).ceil()) as usize).max(1);
        let chunk_iter = vec.chunks(chunk_size);
        let (tx, rx) = channel();

        let mut threads = vec![];

        for chunk in chunk_iter {
            let tx = tx.clone();
            let vec = chunk.to_vec();
            let s1 = s1.clone();
            let s2 = s2.clone();
            let s3 = s3.clone();
            threads.push(thread::spawn(move || {
                // log::info!("Stage 1 generation");
                let vec = stage1::run_vec(s1, vec).unwrap();
                // log::info!("Stage 2 generation");
                let vec = stage2::run_vec(s2, vec);

                let mut packets = vec![];

                // log::info!("Stage 3 generation");
                packets.append(&mut stage3::run_vec(
                    |f, p, v, a| s3.generate_udp_packets(f, p, v, a),
                    vec.udp,
                ));
                packets.append(&mut stage3::run_vec(
                    |f, p, v, a| s3.generate_tcp_packets(f, p, v, a),
                    vec.tcp,
                ));
                packets.append(&mut stage3::run_vec(
                    |f, p, v, a| s3.generate_icmp_packets(f, p, v, a),
                    vec.icmp,
                ));

                packets.sort_unstable();
                tx.send(packets).unwrap();
            }));
        }
        drop(tx); // drop it so we can stop when all threads are over

        let file_out = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&export.outfile)
            .expect("Error opening or creating file");
        let mut pcap_writer =
            PcapWriter::new(BufWriter::new(file_out)).expect("Error writing file");

        for thread in threads {
            thread.join().unwrap();
        }

        let gen_duration = start.elapsed().as_secs_f64();

        let mut total_size = 0;
        log::info!("Pcap export");
        for packet in kmerge(rx) {
            let len = packet.data.len();
            total_size += len;
            pcap_writer
                .write_packet(&PcapPacket::new(packet.timestamp, len as u32, &packet.data))
                .unwrap();
        }
        log::info!(
            "Generation throughput: {}/s",
            HumanBytes(((total_size as f64) / gen_duration) as u64)
        );
    }
}
