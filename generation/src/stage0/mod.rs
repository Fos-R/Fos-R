use crate::structs::*;
use std::time::Duration;
use rand_pcg::Pcg32;
use rand::RngCore;
use rand::SeedableRng;

/// Stage 0: generate timestamps
pub struct UniformGenerator {
    current_ts: Duration,
    window_count: u32,
    remaining: i32,
    rng: Pcg32,
}

impl Iterator for UniformGenerator {
    type Item = SeededData<Duration>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining > 0 {
            self.remaining -= 1;
            Some(SeededData { seed: self.rng.next_u64(), data: self.current_ts })
        } else {
            None
        }
    }
}

impl UniformGenerator {

    pub fn new(seed: u64, initial_ts: Duration, nb_flows: i32) -> Self {
        UniformGenerator { current_ts: initial_ts, window_count: 0, remaining: nb_flows, rng: Pcg32::seed_from_u64(seed) }
    }
}


