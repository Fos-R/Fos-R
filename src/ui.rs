use crate::structs::*;

use indicatif::HumanBytes;
use indicatif::MultiProgress;
use indicatif::{ProgressBar, ProgressState, ProgressStyle};
use std::fmt::Write;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

pub struct Stats {
    pub start_time: Instant, // remove?
    pub packets_target: Option<u64>,
    pub packets_counter: AtomicU64,
    pub bytes_counter: AtomicU64,
    pub pcap_counter: AtomicU64,
    pub early_stop: AtomicBool,
}

impl Default for Stats {
    fn default() -> Self {
        Stats {
            start_time: Instant::now(),
            packets_counter: AtomicU64::new(0),
            packets_target: None,
            bytes_counter: AtomicU64::new(0),
            pcap_counter: AtomicU64::new(0),
            early_stop: AtomicBool::new(false),
        }
    }
}

// For the moment, handles generation statistics only, but it will also take care of the UI

impl Stats {
    pub fn new(packets_target: u64) -> Self {
        Stats {
            start_time: Instant::now(),
            packets_counter: AtomicU64::new(0),
            packets_target: Some(packets_target),
            bytes_counter: AtomicU64::new(0),
            pcap_counter: AtomicU64::new(0),
            early_stop: AtomicBool::new(false),
        }
    }

    pub fn increase(&self, p: &Packets) {
        self.packets_counter
            .fetch_add(p.packets.len() as u64, Ordering::Relaxed);
        self.bytes_counter.fetch_add(
            p.packets.iter().map(|p| p.data.len()).sum::<usize>() as u64,
            Ordering::Relaxed,
        );
    }

    pub fn increase_pcap(&self) {
        self.pcap_counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn should_stop(&self) -> bool {
        if let Some(target) = self.packets_target {
            self.early_stop.load(Ordering::Relaxed)
                || self.packets_counter.load(Ordering::Relaxed) >= target
        } else {
            self.early_stop.load(Ordering::Relaxed)
        }
    }

    pub fn stop_early(&self) {
        self.early_stop.store(true, Ordering::Relaxed);
    }
}

pub fn run(stats: Arc<Stats>, cpu_usage: bool) {
    let child = if cpu_usage {
        Some(
            Command::new("top")
                .arg("-H")
                .arg("-p")
                .arg(std::process::id().to_string())
                .spawn()
                .expect("command failed to start"),
        )
    } else {
        None
    };

    if let Some(target) = stats.packets_target {
        let m = MultiProgress::new();

        let pb_generation = m.add(ProgressBar::new(target));
        // let pb_generation = ProgressBar::new(target);
        {
            let stats = Arc::clone(&stats);
            pb_generation.set_style(
                ProgressStyle::with_template(
                    "{spinner:.green} Generation [{throughput}] [{wide_bar}] ({eta})",
                )
                .unwrap()
                .with_key(
                    "throughput",
                    move |state: &ProgressState, w: &mut dyn Write| {
                        if !state.elapsed().is_zero() {
                            let bc = stats.bytes_counter.load(Ordering::Relaxed);
                            let throughput = (bc as f64) / state.elapsed().as_secs_f64();
                            write!(w, "{}/s", HumanBytes(throughput as u64)).unwrap();
                        }
                    },
                ),
            );
        }

        let pb_pcap = m.add(ProgressBar::new(target));
        pb_pcap.set_style(
            ProgressStyle::with_template("{spinner:.green} PCAP export [{wide_bar}] ({eta})")
                .unwrap()
                .with_key("eta", |state: &ProgressState, w: &mut dyn Write| {
                    write!(w, "{:.1}s", state.eta().as_secs_f64()).unwrap()
                }),
        );

        let mut gen_done = false;
        let mut pcap_done = false;

        while !gen_done || !pcap_done {
            if !gen_done {
                let c = stats.packets_counter.load(Ordering::Relaxed);
                pb_generation.set_position(c);
                if c >= target {
                    gen_done = true;
                    pb_generation.finish_with_message("Generation done");
                }
            }
            if !pcap_done {
                let c = stats.pcap_counter.load(Ordering::Relaxed);
                pb_pcap.set_position(c);
                if c >= target {
                    pcap_done = true;
                    pb_pcap.finish_with_message("Export done");
                }
            }
            thread::sleep(Duration::from_millis(10));
        }

        m.clear().unwrap();
    } else {
        while !stats.should_stop() {
            thread::sleep(Duration::new(5, 0));
            {
                let pc = stats.packets_counter.load(Ordering::Relaxed);
                let bc = stats.bytes_counter.load(Ordering::Relaxed);
                let throughput = (bc as f64)
                    / (Instant::now().duration_since(stats.start_time).as_secs() as f64)
                    / 1_000_000.;
                if throughput < 1. {
                    log::info!("{pc} created packets ({:.2} kbps)", throughput * 1000.);
                } else if throughput < 1000. {
                    log::info!("{pc} created packets ({:.2} Mbps)", throughput);
                } else {
                    log::info!("{pc} created packets ({:.2} Gbps)", throughput / 1000.);
                }
            }
        }
    }
    if let Some(mut c) = child {
        c.kill().expect("command couldn't be killed");
    }
}
