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


const WINDOW_WIDTH_IN_SECS: u64 = 5;

/// Stage 0: generate timestamps. Must implement an Iterator with Item = SeededData<Duration>.
/// Generate a uniform throughput and never stops. It always prepares the next windows (i.e., not
/// the one being sent)
pub struct OnlineUniformGenerator {
    next_ts: Duration, // the start of the S0 generation window = the end of the sending window
    flows_per_window: u64,
    remaining: u64,
    time_distrib: Uniform<u64>,
    rng: Pcg32,
}

impl Iterator for OnlineUniformGenerator {
    type Item = SeededData<Duration>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            // wait until the end of the current window
            if SystemTime::now().duration_since(UNIX_EPOCH).unwrap() > self.next_ts {
                log::warn!("Generation is too slow");
            } else {
                thread::sleep(self.next_ts.saturating_sub(SystemTime::now().duration_since(UNIX_EPOCH).unwrap()));
            }
            self.remaining = self.flows_per_window;
            self.next_ts += Duration::new(WINDOW_WIDTH_IN_SECS, 0);
            self.time_distrib = Uniform::new(self.next_ts.as_millis() as u64, self.next_ts.as_millis() as u64 + 1000 * WINDOW_WIDTH_IN_SECS);
        }
        self.remaining -= 1;
        Some(SeededData { seed: self.rng.next_u64(), data: Duration::from_millis(self.time_distrib.sample(&mut self.rng)) })
    }
}

impl OnlineUniformGenerator {

    pub fn new(seed: u64, flows_per_window: u64) -> Self {
        let next_ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap() + Duration::new(WINDOW_WIDTH_IN_SECS, 0);
        let time_distrib = Uniform::new(next_ts.as_millis() as u64, next_ts.as_millis() as u64 + 1000 * WINDOW_WIDTH_IN_SECS);
        OnlineUniformGenerator { next_ts, remaining: flows_per_window, flows_per_window, rng: Pcg32::seed_from_u64(seed), time_distrib }
    }
}


