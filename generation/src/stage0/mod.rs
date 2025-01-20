use crate::structs::*;
use std::time::Duration;
use rand_pcg::Pcg32;
use rand::RngCore;
use rand::SeedableRng;
use rand::distributions::Uniform;
use rand_distr::Distribution;
use std::time::UNIX_EPOCH;
use std::time::SystemTime;
use std::thread;
use crossbeam_channel::Sender;


const WINDOW_WIDTH_IN_SECS: u64 = 5;

/// Stage 0: generate timestamps.
/// Generate a uniform throughput and never stops. It always prepares the next windows (i.e., not
/// the one being sent)
pub trait Stage0: Iterator<Item=SeededData<Duration>> + Clone + std::marker::Send + 'static {}

#[derive(Debug, Clone)]
pub struct UniformGenerator {
    next_ts: Duration, // the start of the S0 generation window = the end of the sending window
    flows_per_window: u64,
    remaining: u64,
    max_flow_count: u64,
    total_flow_count: u64,
    time_distrib: Uniform<u64>,
    rng: Pcg32,
    online: bool,
}

impl Stage0 for UniformGenerator {}

impl Iterator for UniformGenerator {
    type Item = SeededData<Duration>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            if self.online {
                // wait until the end of the current window
                if SystemTime::now().duration_since(UNIX_EPOCH).unwrap() > self.next_ts {
                    log::warn!("Generation is too slow");
                } else {
                    thread::sleep(self.next_ts.saturating_sub(SystemTime::now().duration_since(UNIX_EPOCH).unwrap()));
                }
            }
            self.remaining = self.flows_per_window;
            self.next_ts += Duration::from_secs(WINDOW_WIDTH_IN_SECS);
            self.time_distrib = Uniform::new(self.next_ts.as_millis() as u64, self.next_ts.as_millis() as u64 + 1000 * WINDOW_WIDTH_IN_SECS);
        }
        self.remaining -= 1;
        self.total_flow_count += 1;
        if self.total_flow_count > self.max_flow_count {
            None
        } else {
            Some(SeededData { seed: self.rng.next_u64(), data: Duration::from_millis(self.time_distrib.sample(&mut self.rng)) })
        }
    }
}

impl UniformGenerator {

    pub fn new(seed: Option<u64>, online: bool, flows_per_window: u64, max_flow_count: u64) -> Self {
        let next_ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap() + Duration::from_secs(WINDOW_WIDTH_IN_SECS);
        let time_distrib = Uniform::new(next_ts.as_millis() as u64, next_ts.as_millis() as u64 + 1000 * WINDOW_WIDTH_IN_SECS);
        let rng = match seed {
            Some(s) => Pcg32::seed_from_u64(s),
            None => Pcg32::from_entropy(),
        };
        UniformGenerator { online, next_ts, max_flow_count, total_flow_count: 0, remaining: flows_per_window, flows_per_window, rng, time_distrib }
    }
}

pub fn run(generator: impl Stage0, tx_s0: Sender<SeededData<Duration>>) {
    log::trace!("Start S0");
    for ts in generator {
        log::trace!("S0 generates {:?}",ts);
        tx_s0.send(ts).unwrap();
    }
    log::trace!("S0 stops");
}
