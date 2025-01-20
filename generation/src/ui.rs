use crate::structs::*;

use std::sync::{Mutex, Arc};
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::{Instant,Duration};

pub struct Stats {
    pub start_time: Instant,
    pub packets_counter: Mutex<u64>,
    pub bytes_counter: Mutex<u64>,
}

impl Default for Stats {
    fn default() -> Self {
        Stats { start_time: Instant::now(), packets_counter: Mutex::default(), bytes_counter: Mutex::default() }
    }
}

// For the moment, handles generation statistics only, but it will also take care of the UI

impl Stats {
    pub fn increase(&self, p: &Packets) {
        let mut pc = self.packets_counter.lock().unwrap();
        *pc += p.packets.len() as u64;
        let mut bc = self.bytes_counter.lock().unwrap();
        *bc += (p.flow.get_data().fwd_total_payload_length + p.flow.get_data().bwd_total_payload_length) as u64;
    }
}

pub fn run(stats: Arc<Stats>, running: Arc<AtomicBool>) {
    loop {
        thread::sleep(Duration::new(1,0));
        {
            let pc = stats.packets_counter.lock().unwrap();
            let bc = stats.bytes_counter.lock().unwrap();
            let throughput = 8. * (*bc as f64) / (Instant::now().duration_since(stats.start_time).as_secs() as f64) / 1_000_000.;
            if throughput < 1000. {
                log::info!("{pc} created packets ({} Mbps)", throughput);
            } else {
                log::info!("{pc} created packets ({} Gbps)", throughput/1000.);
            }
            if !running.load(Ordering::Relaxed) {
                break;
            }
        }
    }
}
