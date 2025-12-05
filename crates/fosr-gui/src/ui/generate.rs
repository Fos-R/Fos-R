use fosr_lib::stage2::tadam;
use fosr_lib::stage2::tadam::AutomataLibrary;
use fosr_lib::config;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use fosr_lib::stats::Target;
use std::time::Duration;
use std::time::UNIX_EPOCH;
use fosr_lib::stage2::tadam::TadamGenerator;
use fosr_lib::stage3;
use fosr_lib::stage0;
use fosr_lib::stage1;
use fosr_lib::stage2;
use std::time::Instant;
use std::fs::OpenOptions;
use pcap_file::pcap::PcapWriter;
use std::io::BufWriter;
use pcap_file::pcap::PcapPacket;
use std::time::SystemTime;
use chrono::DateTime;
use chrono::Offset;
use chrono::TimeZone;
use chrono_tz::Tz;
use indicatif::HumanBytes;

struct Profile {
    automata: stage2::tadam::AutomataLibrary,
    // patterns: stage1::flowchronicle::PatternSet,
    bn: stage1::bayesian_networks::BayesianModel,
    time_bins: stage0::TimeProfile,
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
                // config: config::import_config(
                //     &fs::read_to_string(Path::new(path).join("profile.toml"))
                //         .expect("Cannot access the configuration file."),
                // ),
                bn: stage1::bayesian_networks::BayesianModel::load().unwrap(), // TODO indiquer le chemin
                // patterns: stage1::flowchronicle::PatternSet::from_file(
                //     Path::new(path)
                //         .join("patterns/patterns.json")
                //         .to_str()
                //         .unwrap(),
                // )
                // .expect("Cannot load patterns"),
                time_bins: stage0::TimeProfile::from_file(
                    Path::new(path).join("time_profile.json").to_str().unwrap(),
                )
                .unwrap(),
            }
        } else {
            log::info!("Load default profile");
            Profile {
                automata: stage2::tadam::AutomataLibrary::default(),
                bn: stage1::bayesian_networks::BayesianModel::load().unwrap(), // TODO
                // patterns: stage1::flowchronicle::PatternSet::default(),
                time_bins: stage0::TimeProfile::default(),
            }
        }
    }

    fn load_config(&mut self, content: &str) {
        let config = config::import_config(content);
        self.bn.apply_config(&config).expect("Fatal error");
    }
}

struct ExportParams {
    /// the output file path
    outfile: String,
    /// whether to order the pcap once the generation has ended
    order_pcap: bool,
}

#[derive(Default, Debug)]
pub struct Params {
    pub seed: Option<u64>,
    pub profile: Option<String>,
    pub outfile: String,
    pub packets_count: Option<u64>,
    pub order_pcap: bool,
    pub start_time: String,
    pub duration: String,
    pub taint: bool,
}

pub fn generate(seed: Option<u64>,
                profile: Option<String>,
                outfile: String,
                packets_count: Option<u64>,
                order_pcap: bool,
                start_time: Option<String>,
                duration: Option<String>,
                taint: bool,
) {
    // load the models
    let model: Option<String> = None;
    let mut model = Profile::load(model.as_deref());
    if let Some(config) = profile {
        model.load_config(&config);
    }
    let automata_library = Arc::new(model.automata);
    // let patterns = Arc::new(model.patterns);
    let bn = Arc::new(model.bn);

    // handle the parameters: either there is a packet count target or a duration
    let (target, duration) = match (packets_count, duration) {
        (None, Some(d)) => {
            let d = humantime::parse_duration(&d).expect("Duration could not be parsed.");
            log::info!("Generating a pcap of {d:?}");
            (Target::GenerationDuration(d), Some(d))
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
//
    let tz = Some("CET"); // TODO: passer en paramètre
    let tz_offset = match tz {
        Some(tz_str) => {
            // Gérer le timezone depuis un string
            let tz: Tz = tz_str.parse().expect("Could not parse the timezone");
            let date = DateTime::from_timestamp(initial_ts.as_secs() as i64, 0)
                .unwrap()
                .naive_utc();
            let tz = tz.offset_from_utc_datetime(&date).fix();
            log::info!("Using {tz_str} timezone (UTC{tz})");
            tz
        }
        None => {
            // détecter le timezone
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


    let s0 = stage0::BinBasedGenerator::new(
        seed,
        false,
        None,
        model.time_bins,
        initial_ts,
        duration,
        tz_offset,
    );
    let s1 = stage1::bayesian_networks::BNGenerator::new(bn, false);
    let s2 = stage2::tadam::TadamGenerator::new(automata_library);
    let s3 = stage3::Stage3::new(taint);
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
//
//
fn run_monothread(
    export: ExportParams,
    s0: impl stage0::Stage0,
    s1: impl stage1::Stage1,
    s2: impl stage2::Stage2,
    s3: stage3::Stage3,
) {
    let start = Instant::now();
//
    log::info!("Stage 0 generation");
    let vec = stage0::run_vec(s0);
    log::info!("Stage 1 generation");
    let vec = stage1::run_vec(s1, vec).unwrap();
    log::info!("Stage 2 generation");
    let vec = stage2::run_vec(s2, vec);
//
    let mut all_packets = vec![];
//
    log::info!("Stage 3 generation");
    all_packets.append(&mut stage3::run_vec(
        |f, p, v, a| s3.generate_udp_packets(f, p, v, a),
        vec.udp,
    ));
    all_packets.append(&mut stage3::run_vec(
        |f, p, v, a| s3.generate_tcp_packets(f, p, v, a),
        vec.tcp,
    ));
    all_packets.append(&mut stage3::run_vec(
        |f, p, v, a| s3.generate_icmp_packets(f, p, v, a),
        vec.icmp,
    ));
//
    let gen_duration = start.elapsed().as_secs_f64();
    let total_size = all_packets.iter().map(|p| p.data.len()).sum::<usize>() as u64;
    log::info!(
        "Generation throughput: {}/s",
        HumanBytes(((total_size as f64) / gen_duration) as u64)
    );
//
    if export.order_pcap {
        log::info!("Sorting the packets");
        all_packets.sort_unstable();
    }
//
    let file_out = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&export.outfile)
        .expect("Error opening or creating file");
    let mut pcap_writer = PcapWriter::new(BufWriter::new(file_out)).expect("Error writing file");
//
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
