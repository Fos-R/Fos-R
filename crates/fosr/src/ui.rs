use crate::structs::*;

use indicatif::HumanBytes;
use indicatif::{ProgressBar, ProgressState, ProgressStyle};
use std::fmt::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

pub struct Stats {
    pub packets_target: Option<u64>,
    pub packets_counter: AtomicU64,
    pub bytes_counter: AtomicU64,
    pub early_stop: AtomicBool,
    pub duration_target: Option<u64>, // in secs
    pub current_duration: AtomicU64,  // in secs
    pub progress_bar: ProgressBar,
    pub received_packets: AtomicU64,
    pub ignored_packets: AtomicU64,
    pub sent_packets: AtomicU64,
}

impl Default for Stats {
    fn default() -> Self {
        Stats {
            packets_counter: AtomicU64::new(0),
            packets_target: None,
            bytes_counter: AtomicU64::new(0),
            early_stop: AtomicBool::new(false),
            duration_target: None,
            current_duration: AtomicU64::new(0),
            progress_bar: ProgressBar::new(0),
            received_packets: AtomicU64::new(0),
            ignored_packets: AtomicU64::new(0),
            sent_packets: AtomicU64::new(0),
        }
    }
}

pub enum Target {
    PacketCount(u64),
    Duration(Duration),
    None,
}

// For the moment, handles generation statistics only, but it will also take care of the UI

impl Stats {
    pub fn new(target: Target) -> Self {
        let (packets_target, duration_target, target) = match target {
            Target::PacketCount(p) => (Some(p), None, p),
            Target::Duration(d) => (None, Some(d.as_secs()), d.as_secs()),
            Target::None => (None, None, 0),
        };
        Stats {
            packets_counter: AtomicU64::new(0),
            packets_target,
            bytes_counter: AtomicU64::new(0),
            early_stop: AtomicBool::new(false),
            duration_target,
            current_duration: AtomicU64::new(0),
            progress_bar: ProgressBar::new(target),
            received_packets: AtomicU64::new(0),
            ignored_packets: AtomicU64::new(0),
            sent_packets: AtomicU64::new(0),
        }
    }

    pub fn set_current_duration(&self, secs: u64) {
        self.current_duration.fetch_max(secs, Ordering::Relaxed);
    }

    pub fn packet_ignored(&self) {
        self.ignored_packets.fetch_add(1, Ordering::Relaxed);
    }

    pub fn packet_received(&self) {
        self.received_packets.fetch_add(1, Ordering::Relaxed);
    }

    pub fn packet_sent(&self) {
        self.sent_packets.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increase(&self, p: &Packets) {
        self.packets_counter
            .fetch_add(p.packets.len() as u64, Ordering::Relaxed);
        self.bytes_counter.fetch_add(
            p.packets.iter().map(|p| p.data.len()).sum::<usize>() as u64,
            Ordering::Relaxed,
        );
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

fn update_progress_bar(stats: Arc<Stats>, position: &AtomicU64, target: u64) {
    loop {
        let c = position.load(Ordering::Relaxed);
        stats.progress_bar.set_position(c);
        if c >= target || stats.should_stop() {
            stats.progress_bar.finish();
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

pub fn run(stats: Arc<Stats>) {
    if stats.packets_target.is_some() || stats.duration_target.is_some() {
        let stats2 = Arc::clone(&stats);
        stats.progress_bar.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} Generation [{throughput}] [{wide_bar}] ({eta})",
            )
            .unwrap()
            .with_key(
                "throughput",
                move |state: &ProgressState, w: &mut dyn Write| {
                    if !state.elapsed().is_zero() {
                        let bc = stats2.bytes_counter.load(Ordering::Relaxed);
                        let throughput = (bc as f64) / state.elapsed().as_secs_f64();
                        write!(w, "{}/s", HumanBytes(throughput as u64)).unwrap();
                    }
                },
            ),
        );

        if let Some(target) = stats.packets_target {
            update_progress_bar(stats.clone(), &stats.packets_counter, target);
        } else if let Some(target) = stats.duration_target {
            update_progress_bar(stats.clone(), &stats.current_duration, target);
        }
    } else {
        while !stats.should_stop() {
            for i in 0..10 {
                thread::sleep(Duration::new(1, 0));
                if stats.should_stop() || i == 0{
                    let pc = stats.packets_counter.load(Ordering::Relaxed);
                    let sp = stats.sent_packets.load(Ordering::Relaxed);
                    let rp = stats.received_packets.load(Ordering::Relaxed);
                    let ip = stats.ignored_packets.load(Ordering::Relaxed);
                    log::info!(
                        "{pc} created packets, {sp} sent and {rp} received (including {ip} ignored)"
                    );
                    if stats.should_stop() {
                        break;
                    }

                }
            }
        }
    }
}
