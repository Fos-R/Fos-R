//! Core PCAP generation: runs the 4-stage Fos-R pipeline (S0→S1→S2→S3).

use chrono::{DateTime, Offset, TimeZone};
use chrono_tz::Tz;
use fosr_lib::{
    models, stage1, stage2, stage3, stage3::tadam::TadamGenerator, stage4, stats::Target,
};
use indicatif::HumanBytes;
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::time::UNIX_EPOCH as STD_UNIX_EPOCH;
use web_time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Entry point for PCAP generation. Runs the 4-stage pipeline and sends results via channels.
///
/// Returns `Ok(())` on success, or `Err(message)` if generation fails.
pub fn generate(
    model: models::ArcModels,
    seed: Option<u64>,
    order_pcap: bool,
    start_time: Option<String>,
    duration: String,
    taint: bool,
    timezone: Option<String>,
    progress_sender: Option<Sender<f32>>,
    pcap_sender: Option<Sender<Vec<u8>>>,
    throughput_sender: Option<Sender<String>>,
    cancelled: Arc<AtomicBool>,
) -> Result<(), String> {
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
    // let automata_library = Arc::new(model.automata);
    // let bayesian_network = Arc::new(model.bn);

    // Handle the parameters: either there is a packet count target or a duration
    let parsed_duration = humantime::parse_duration(&duration)
        .map_err(|e| format!("Invalid duration '{}': {}", duration, e))?;
    log::info!("Generating a pcap of {parsed_duration:?}");
    let _target = Target::GenerationDuration(parsed_duration);

    if let Some(s) = seed {
        log::info!("Generating with seed {s}");
    }
    let initial_ts = parse_start_time(start_time)?;
    let tz_offset = resolve_timezone_offset(timezone, initial_ts)?;

    let s0 = stage1::BinBasedGenerator::new(
        seed,
        false,
        None,
        model.time_bins,
        initial_ts,
        Some(parsed_duration),
        tz_offset,
    );
    // We duplicate the BN so the user can change the network while the generation is ongoing
    // without perturbating the generation
    let bn = model.bn.write().unwrap().clone();
    let s1 = stage2::bayesian_networks::BNGenerator::new(Arc::new(RwLock::new(bn)), false);
    let s2 = TadamGenerator::new(model.automata);
    let s3 = stage4::Stage4::new(taint);
    log::info!("Run single thread");
    execute_generation_pipeline(
        order_pcap,
        s0,
        s1,
        s2,
        s3,
        send_progress,
        send_pcap,
        throughput_sender,
        cancelled,
    )
}

/// Parses start time from RFC3339 string, Unix timestamp, or returns current time if None.
fn parse_start_time(start_time: Option<String>) -> Result<Duration, String> {
    match start_time {
        Some(start_time) => {
            // try to parse a date
            if let Ok(d) = humantime::parse_rfc3339_weak(&start_time) {
                d.duration_since(STD_UNIX_EPOCH)
                    .map_err(|e| format!("Invalid start time: {}", e))
            } else if let Ok(n) = start_time.parse::<u64>() {
                Ok(Duration::from_secs(n))
            } else {
                Err(format!(
                    "Could not parse start time '{}' (expected RFC3339 date or Unix timestamp)",
                    start_time
                ))
            }
        }
        None => SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("Failed to get current time: {}", e)),
    }
}

/// Resolves timezone offset from IANA string, or detects local timezone if None.
fn resolve_timezone_offset(
    timezone: Option<String>,
    initial_ts: Duration,
) -> Result<chrono::FixedOffset, String> {
    let date = DateTime::from_timestamp(initial_ts.as_secs() as i64, 0)
        .ok_or_else(|| "Invalid timestamp: value out of range".to_string())?
        .naive_utc();

    match timezone {
        Some(tz_str) => {
            let tz = tz_str
                .parse::<Tz>()
                .map_err(|e| format!("Invalid timezone '{}': {}", tz_str, e))?;
            let offset = tz.offset_from_utc_datetime(&date).fix();
            log::info!("Using {tz_str} timezone (UTC{offset})");
            Ok(offset)
        }
        None => {
            // Detect the local timezone
            let offset = chrono::Local::now()
                .timezone()
                .offset_from_local_datetime(&date)
                .single()
                .ok_or_else(|| {
                    "Could not determine local timezone (ambiguous or invalid date)".to_string()
                })?
                .fix();
            log::info!("Using local timezone (UTC{offset})");
            Ok(offset)
        }
    }
}

/// Executes the 4-stage pipeline sequentially with cancellation support.
fn execute_generation_pipeline(
    order_pcap: bool,
    s0: impl stage1::Stage1,
    s1: impl stage2::Stage2,
    s2: impl stage3::Stage3,
    s3: stage4::Stage4,
    send_progress: impl Fn(f32),
    send_pcap: impl Fn(Vec<u8>),
    throughput_sender: Option<Sender<String>>,
    cancelled: Arc<AtomicBool>,
) -> Result<(), String> {
    let is_cancelled = || cancelled.load(Ordering::Relaxed);

    let start = Instant::now();

    log::info!("Stage 1 generation");
    let stage1_output = stage1::run_vec(s0);
    if is_cancelled() {
        log::info!("Generation cancelled after stage 0");
        return Ok(());
    }
    send_progress(0.2);

    log::info!("Stage 2 generation");
    let stage2_output =
        stage2::run_vec(s1, stage1_output).map_err(|e| format!("Stage 1 failed: {}", e))?;
    if is_cancelled() {
        log::info!("Generation cancelled after stage 1");
        return Ok(());
    }
    send_progress(0.4);

    log::info!("Stage 3 generation");
    let stage3_output = stage3::run_vec(s2, stage2_output);
    if is_cancelled() {
        log::info!("Generation cancelled after stage 2");
        return Ok(());
    }
    send_progress(0.6);

    log::info!("Stage 4 generation");
    let stage4_packets = generate_stage4_packets(&s3, stage3_output, &is_cancelled);
    let mut all_packets = match stage4_packets {
        Some(p) => p,
        None => return Ok(()), // Cancelled
    };
    send_progress(0.8);

    let gen_duration = start.elapsed().as_secs_f64();
    let total_size = all_packets.iter().map(|p| p.data.len()).sum::<usize>() as u64;
    let throughput_str = format!(
        "{}/s",
        HumanBytes(((total_size as f64) / gen_duration) as u64)
    );
    log::info!("Generation throughput: {throughput_str}");
    if let Some(sender) = &throughput_sender {
        let _ = sender.send(throughput_str);
    }

    if is_cancelled() {
        log::info!("Generation cancelled");
        return Ok(());
    }

    if order_pcap {
        log::info!("Sorting the packets");
        all_packets.sort_unstable();
    }

    if is_cancelled() {
        log::info!("Generation cancelled");
        return Ok(());
    }

    let pcap_bytes =
        stage4::to_pcap_vec(&all_packets).map_err(|e| format!("Failed to create PCAP: {}", e))?;
    send_pcap(pcap_bytes);
    send_progress(1.0);
    Ok(())
}

/// Generates UDP, TCP, and ICMP packets. Returns None if cancelled.
fn generate_stage4_packets(
    s3: &stage4::Stage4,
    vec: stage3::S3Vector,
    is_cancelled: &impl Fn() -> bool,
) -> Option<Vec<fosr_lib::Packet>> {
    let mut all_packets = vec![];
    let stats = Arc::new(fosr_lib::stats::Stats::new(fosr_lib::stats::Target::None));
    {
        let stats = stats.clone();

        all_packets.extend(stage4::run_vec(
            |f, p, v, a| s3.generate_udp_packets(f, p, v, a),
            vec.udp,
            stats,
        ));
    }
    if is_cancelled() {
        log::info!("Generation cancelled during stage 3");
        return None;
    }
    {
        let stats = stats.clone();

        all_packets.extend(stage4::run_vec(
            |f, p, v, a| s3.generate_tcp_packets(f, p, v, a),
            vec.tcp,
            stats,
        ));
    }
    if is_cancelled() {
        log::info!("Generation cancelled during stage 3");
        return None;
    }
    {
        let stats = stats.clone();

        all_packets.extend(stage4::run_vec(
            |f, p, v, a| s3.generate_icmp_packets(f, p, v, a),
            vec.icmp,
            stats,
        ));
    }
    if is_cancelled() {
        log::info!("Generation cancelled during stage 3");
        return None;
    }

    Some(all_packets)
}
