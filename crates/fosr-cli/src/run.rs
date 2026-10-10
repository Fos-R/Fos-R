use fosr_lib::export;
#[cfg(feature = "net_injection")]
use fosr_lib::inject;
use fosr_lib::stage1;
use fosr_lib::stage2;
use fosr_lib::stage3;
use fosr_lib::stage4;
use fosr_lib::stats;
use fosr_lib::{
    Flow, ICMPPacketInfo, L4Proto, Packets, PacketsIR, PacketsRecycler, SeededData, TCPPacketInfo,
    TimePoint, UDPPacketInfo, inject,
};

use std::collections::HashMap;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::BufWriter;
use std::net::Ipv4Addr;
use std::process;
use std::sync::Arc;
use std::sync::mpsc::channel;
use std::thread;
use std::time::Instant;

use crate::cmd;
use crossbeam_channel::bounded;
use indicatif::HumanBytes;
use itertools::kmerge;
use pcap_file::pcap::{PcapPacket, PcapWriter};
#[cfg(feature = "net_injection")]
use pnet::{datalink, ipnetwork::IpNetwork};

const CHANNEL_SIZE: usize = 50;

pub struct InjectParam<T: inject::NetEnabler> {
    #[allow(unused)]
    pub net_enabler: T,
    #[allow(unused)]
    pub injection_algo: cmd::InjectionAlgo,
}

pub enum ExportDestination {
    FileName(String),
    #[cfg(target_os = "linux")]
    #[allow(unused)]
    Writer(File),
}

pub struct ExportParams {
    /// the output file path
    pub outfile: ExportDestination,
    /// whether to order the pcap once the generation has ended
    pub order_pcap: bool,
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
/// - `s1`: a stage 0 implementation
/// - `s2`: a stage 1 implementation
/// - `s3`: a stage 2 implementation
/// - `s4`: a stage 3 implementation
/// - `stats`: an Arc to a structure containing generation statistics
/// - `s5net`: an optional network enabler
#[allow(clippy::too_many_arguments)]
pub fn run_efficient<T: inject::NetEnabler>(
    local_interfaces: Vec<Ipv4Addr>,
    export: Option<ExportParams>,
    s1: impl stage1::Stage1,
    s2: (impl stage2::Stage2, usize),
    s3: (impl stage3::Stage3, usize),
    s4: (stage4::Stage4, usize),
    stats: Arc<stats::Stats>,
    #[allow(unused)] s5net: Option<InjectParam<T>>,
) -> Result<(), String> {
    log::debug!("Generation with \"efficient\" profile");
    let (s2, s2_count) = s2;
    let (s3, s3_count) = s3;
    let (s4, s4_count) = s4;

    let mut threads = vec![];
    let mut gen_threads = vec![];
    let mut export_threads = vec![];

    // block to automatically drop channels before the joins
    {
        // Channels creation
        let (tx_s1, rx_s2) = bounded::<SeededData<TimePoint>>(CHANNEL_SIZE);
        let (tx_s2, rx_s3) = bounded::<SeededData<Flow>>(CHANNEL_SIZE);
        let (tx_s3_tcp, rx_s4_tcp) = bounded::<SeededData<PacketsIR<TCPPacketInfo>>>(CHANNEL_SIZE);
        let (tx_s3_udp, rx_s4_udp) = bounded::<SeededData<PacketsIR<UDPPacketInfo>>>(CHANNEL_SIZE);
        let (tx_s3_icmp, rx_s4_icmp) =
            bounded::<SeededData<PacketsIR<ICMPPacketInfo>>>(CHANNEL_SIZE);
        let tx_s3 = stage3::S3Sender {
            tcp: tx_s3_tcp,
            udp: tx_s3_udp,
            icmp: tx_s3_icmp,
        };
        // TODO: only create if online
        let mut tx_s4 = HashMap::new();
        let mut rx_s5 = HashMap::new();
        for proto in L4Proto::iter() {
            let (tx, rx) = bounded::<Packets>(CHANNEL_SIZE);
            rx_s5.insert(proto, rx);
            tx_s4.insert(proto, tx);
        }
        let (tx_s4_to_pcap, rx_pcap) = thingbuf::mpsc::blocking::with_recycle::<
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
        let builder = thread::Builder::new().name("Stage1".into());
        let stats_s1 = Arc::clone(&stats);
        gen_threads.push(
            builder
                .spawn(move || {
                    let _ = stage1::run_channel(s1, tx_s1, stats_s1);
                })
                .map_err(|e| e.to_string())?,
        );

        // STAGE 1

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
                    .map_err(|e| e.to_string())?,
            );
        }

        // STAGE 2

        for _ in 0..s3_count {
            let rx_s3 = rx_s3.clone();
            let tx_s3 = tx_s3.clone();
            let s3 = s3.clone();
            let stats = Arc::clone(&stats);
            let builder = thread::Builder::new().name("Stage3".into());
            gen_threads.push(
                builder
                    .spawn(move || {
                        let _ = stage3::run_channel(s3, rx_s3, tx_s3, stats);
                    })
                    .map_err(|e| e.to_string())?,
            );
        }

        // STAGE 3

        for (proto, tx) in tx_s4 {
            for _ in 0..s4_count {
                let tx = if local_interfaces.is_empty() {
                    None
                } else {
                    Some(tx.clone())
                };
                let tx_s4_to_pcap = tx_s4_to_pcap.clone();
                let s4 = s4.clone();
                let stats = Arc::clone(&stats);
                let local_interfaces = local_interfaces.clone();

                let builder = thread::Builder::new().name(format!("Stage4-{proto:?}"));
                match proto {
                    L4Proto::TCP => {
                        let rx_s4_tcp = rx_s4_tcp.clone();
                        gen_threads.push(
                            builder
                                .spawn(move || {
                                    let _ = stage4::run_channel(
                                        |f, p, v, a| s4.generate_tcp_packets(f, p, v, a),
                                        &local_interfaces,
                                        rx_s4_tcp,
                                        tx,
                                        tx_s4_to_pcap,
                                        stats,
                                        do_export,
                                    );
                                })
                                .map_err(|e| e.to_string())?,
                        );
                    }
                    L4Proto::UDP => {
                        let rx_s4_udp = rx_s4_udp.clone();
                        gen_threads.push(
                            builder
                                .spawn(move || {
                                    let _ = stage4::run_channel(
                                        |f, p, v, a| s4.generate_udp_packets(f, p, v, a),
                                        &local_interfaces,
                                        rx_s4_udp,
                                        tx,
                                        tx_s4_to_pcap,
                                        stats,
                                        do_export,
                                    );
                                })
                                .map_err(|e| e.to_string())?,
                        );
                    }
                    L4Proto::ICMP => {
                        let rx_s4_icmp = rx_s4_icmp.clone();
                        gen_threads.push(
                            builder
                                .spawn(move || {
                                    let _ = stage4::run_channel(
                                        |f, p, v, a| s4.generate_icmp_packets(f, p, v, a),
                                        &local_interfaces,
                                        rx_s4_icmp,
                                        tx,
                                        tx_s4_to_pcap,
                                        stats,
                                        do_export,
                                    );
                                })
                                .map_err(|e| e.to_string())?,
                        );
                    }
                }
            }
        }

        // PCAP EXPORT

        let builder = thread::Builder::new().name("Pcap-export".into());
        export_threads.push(if let Some(export) = export {
            builder
                .spawn(move || match export.outfile {
                    ExportDestination::FileName(s) => {
                        export::run_export(rx_pcap, &s, export.order_pcap)
                    }
                    ExportDestination::Writer(w) => {
                        export::run_export_to_writer(rx_pcap, &w, export.order_pcap)
                    }
                })
                .map_err(|e| e.to_string())?
        } else {
            // if there is no export, we still need to consume the packets
            builder
                .spawn(move || {
                    export::run_dummy_export(rx_pcap);
                })
                .map_err(|e| e.to_string())?
        });

        // STAGE 4 (injection mode only)
        #[cfg(feature = "net_injection")]
        if let Some(s5net) = s5net {
            let stats = Arc::clone(&stats);
            let builder = thread::Builder::new().name("inject".into());
            gen_threads.push(
                builder
                    .spawn(move || match s5net.injection_algo {
                        cmd::InjectionAlgo::Fast => {
                            inject::start_fast(s5net.net_enabler, rx_s5, stats)
                        }
                        cmd::InjectionAlgo::Reliable => {
                            inject::start_reliable(s5net.net_enabler, rx_s5, stats)
                        }
                    })
                    .map_err(|e| e.to_string())?,
            );
        }
    }

    {
        let stats = Arc::clone(&stats);
        let builder = thread::Builder::new().name("Monitoring".into());
        threads.push(
            builder
                .spawn(move || stats::show_progression(stats))
                .map_err(|e| e.to_string())?,
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
    Ok(())
}

/// Run the generation with very little contention, but the generated dataset must fit in RAM.
/// Cannot be used for injection
pub fn run_fast(
    export: ExportParams,
    s1: impl stage1::Stage1,
    s2: impl stage2::Stage2,
    s3: impl stage3::Stage3,
    s4: stage4::Stage4,
    jobs: usize,
    stats: Arc<stats::Stats>,
) -> Result<(), String> {
    log::debug!("Generation with \"fast\" profile");
    // TODO: remettre "stats", ctrlc, etc.
    let start = Instant::now();

    let vec = stage1::run_vec(s1);
    if vec.is_empty() {
        log::error!("No generated data: duration is too small");
    } else {
        let chunk_size = (((vec.len() as f64) / (jobs as f64).ceil()) as usize).max(1);
        let chunk_iter = vec.chunks(chunk_size);
        let (tx, rx) = channel();

        // Handle ctrl+C
        ctrlc::set_handler(move || {
            process::exit(1);
        })
        .expect("Error setting Ctrl-C handler");

        let mut threads = vec![];

        // {
        //     let stats = Arc::clone(&stats);
        //     let builder = thread::Builder::new().name("Monitoring".into());
        //     threads.push(
        //         builder
        //             .spawn(move || stats::show_progression(stats))
        //             .unwrap(),
        //     );
        // }

        for chunk in chunk_iter {
            let tx = tx.clone();
            let vec = chunk.to_vec();
            let s2 = s2.clone();
            let s3 = s3.clone();
            let s4 = s4.clone();
            let stats = Arc::clone(&stats);
            threads.push(thread::spawn(move || {
                // log::info!("Stage 1 generation");
                let vec = stage2::run_vec(s2, vec).unwrap();
                // log::info!("Stage 2 generation");
                let vec = stage3::run_vec(s3, vec);

                let mut packets = vec![];
                {
                    let stats = Arc::clone(&stats);
                    // log::info!("Stage 3 generation");
                    packets.append(&mut stage4::run_vec(
                        |f, p, v, a| s4.generate_udp_packets(f, p, v, a),
                        vec.udp,
                        stats,
                    ));
                }
                {
                    let stats = Arc::clone(&stats);
                    packets.append(&mut stage4::run_vec(
                        |f, p, v, a| s4.generate_tcp_packets(f, p, v, a),
                        vec.tcp,
                        stats,
                    ));
                }
                packets.append(&mut stage4::run_vec(
                    |f, p, v, a| s4.generate_icmp_packets(f, p, v, a),
                    vec.icmp,
                    stats,
                ));
                packets.sort_unstable();
                tx.send(packets).unwrap();
            }));
        }
        drop(tx); // drop it so we can stop when all threads are over

        let writer = match export.outfile {
            ExportDestination::FileName(outfile) => OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&outfile)
                .expect("Error opening or creating file"),
            ExportDestination::Writer(writer) => writer,
        };
        let mut pcap_writer = PcapWriter::new(BufWriter::new(writer)).expect("Error writing file");
        for thread in threads {
            thread.join().unwrap();
        }

        log::info!("Generation complete");

        let gen_duration = start.elapsed().as_secs_f64();

        let mut total_size = 0;
        let mut pkt_number = 0;
        log::info!("Pcap export");
        for packet in kmerge(rx) {
            let len = packet.data.len();
            total_size += len;
            pkt_number += 1;
            pcap_writer
                .write_packet(&PcapPacket::new(packet.timestamp, len as u32, &packet.data))
                .map_err(|e| e.to_string())?;
        }
        log::info!(
            "Generation throughput: {}/s, {:.3}/MPPS",
            HumanBytes(((total_size as f64) / gen_duration) as u64),
            (f64::from(pkt_number) / (1_000_000f64 * gen_duration))
        );
    }
    Ok(())
}
