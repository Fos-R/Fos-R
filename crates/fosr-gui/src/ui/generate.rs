use std::fs;
use std::fs::OpenOptions;
use std::io::BufWriter;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use fosr::{config, stage0, stage1, stage2, stage3, stats::Target};
use indicatif::HumanBytes;
use pcap_file::pcap::{PcapPacket, PcapWriter};

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

struct ExportParams {
    /// the output file path
    outfile: String,
    /// whether to order the pcap once the generation has ended
    order_pcap: bool,
}

#[derive(Default)]
pub struct Params {
    pub seed: Option<u64>,
    pub profile: Option<String>,
    pub outfile: String,
    pub packets_count: Option<u64>,
    pub order_pcap: bool,
    pub start_time: Option<String>,
    pub duration: Option<String>,
    pub taint: bool
}

pub fn generate(seed: Option<u64>,
                profile: Option<String>,
                outfile: String,
                packets_count: Option<u64>,
                order_pcap: bool,
                start_time: Option<String>,
                duration: Option<String>,
                taint: bool
    ) {
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
    log::info!("Run monothread");
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
}


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
    log::info!(
        "Generation throughput: {}/s",
        HumanBytes(((total_size as f64) / gen_duration) as u64)
    );

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