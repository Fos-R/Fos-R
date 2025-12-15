use chrono::{DateTime, Offset, TimeZone};
use chrono_tz::Tz;
use fosr_lib::{
    models, stage0, stage1, stage2, stage2::tadam::TadamGenerator, stage3, stats::Target,
};
use indicatif::HumanBytes;
use std::sync::{Arc, mpsc::Sender};
use std::time::UNIX_EPOCH as STD_UNIX_EPOCH;
use web_time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub fn generate(
    seed: Option<u64>,
    profile: Option<String>,
    order_pcap: bool,
    start_time: Option<String>,
    duration: String,
    taint: bool,
    timezone: Option<String>,
    progress_sender: Option<Sender<f32>>,
    pcap_sender: Option<Sender<Vec<u8>>>,
) {
    // Create a closure to send progress updates
    let send_progress = |progress: f32| {
        if let Some(sender) = &progress_sender {
            let _ = sender.send(progress);
        }
    };

    // Create a closure to send pcap data
    let send_pcap = |pcap_bytes: Vec<u8>| {
        if let Some(sender) = &pcap_sender {
            let _ = sender.send(pcap_bytes);
        }
    };

    // Load the models
    let source = models::ModelsSource::Legacy;
    let mut model = models::Models::from_source(source).unwrap();
    if let Some(config) = profile {
        model = model.with_string_config(&config).unwrap();
    }

    let automata_library = Arc::new(model.automata);
    let bn = Arc::new(model.bn);

    // Handle the parameters: either there is a packet count target or a duration
    let d = humantime::parse_duration(&duration).expect("Duration could not be parsed.");
    log::info!("Generating a pcap of {d:?}");
    let _target = Target::GenerationDuration(d);
    let duration = Some(d);

    if let Some(s) = seed {
        log::info!("Generating with seed {s}");
    }
    let initial_ts: Duration = if let Some(start_time) = start_time {
        // try to parse a date
        if let Ok(d) = humantime::parse_rfc3339_weak(&start_time) {
            d.duration_since(STD_UNIX_EPOCH).unwrap()
        } else if let Ok(n) = start_time.parse::<u64>() {
            Duration::from_secs(n)
        } else {
            panic!("Could not parse start time");
        }
    } else {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
    };

    let tz_offset = match timezone {
        Some(tz_str) => {
            let tz = tz_str.parse::<Tz>().expect("Could not parse the timezone");
            let date = DateTime::from_timestamp(initial_ts.as_secs() as i64, 0)
                .unwrap()
                .naive_utc();
            let tz = tz.offset_from_utc_datetime(&date).fix();
            log::info!("Using {tz_str} timezone (UTC{tz})");
            tz
        }
        None => {
            // Detect the local timezone
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
    let s2 = TadamGenerator::new(automata_library);
    let s3 = stage3::Stage3::new(taint);
    log::info!("Run monothread");
    run_monothread(order_pcap, s0, s1, s2, s3, send_progress, send_pcap);
}

fn run_monothread(
    order_pcap: bool,
    s0: impl stage0::Stage0,
    s1: impl stage1::Stage1,
    s2: impl stage2::Stage2,
    s3: stage3::Stage3,
    send_progress: impl Fn(f32),
    send_pcap: impl Fn(Vec<u8>),
) {
    let start = Instant::now();

    log::info!("Stage 0 generation");
    let vec = stage0::run_vec(s0);
    send_progress(0.2);

    log::info!("Stage 1 generation");
    let vec = stage1::run_vec(s1, vec).unwrap();
    send_progress(0.4);

    log::info!("Stage 2 generation");
    let vec = stage2::run_vec(s2, vec);
    send_progress(0.6);

    let mut all_packets = vec![];
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
    send_progress(0.8);

    let gen_duration = start.elapsed().as_secs_f64();
    let total_size = all_packets.iter().map(|p| p.data.len()).sum::<usize>() as u64;
    log::info!(
        "Generation throughput: {}/s",
        HumanBytes(((total_size as f64) / gen_duration) as u64)
    );

    if order_pcap {
        log::info!("Sorting the packets");
        all_packets.sort_unstable();
    }

    let pcap_bytes = stage3::to_pcap_vec(&all_packets).expect("Error converting to pcap");
    send_pcap(pcap_bytes);
    send_progress(1.0);
}
