#![allow(dead_code)] // TODO
#![allow(unused_variables)]

use crate::structs::*;
use std::time::Duration;
use rand_pcg::Pcg32;
use rand::RngCore;
use rand::SeedableRng;

pub struct TimeDistribution {}

/// Stage 0: generate timestamps
pub struct Stage0 {
    current_ts: Duration,
    window_count: u32,
    remaining: i32,
    time_distrib: TimeDistribution,
    rng: Pcg32,
}

impl Iterator for Stage0 {
    type Item = SeededData<Duration>; // TODO
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining > 0 {
            self.remaining -= 1;
            Some(SeededData { seed: self.rng.next_u64(), data: self.current_ts })
        } else {
            None
        }
    }
}

impl Stage0 {

    pub fn new(seed: u64, time_distrib: TimeDistribution, initial_ts: Duration, nb_flows: i32) -> Self {
        Stage0 { current_ts: initial_ts, window_count: 0, remaining: nb_flows, time_distrib, rng: Pcg32::seed_from_u64(seed) }
    }

}

pub fn import_time_distribution(filename: &str) -> TimeDistribution {
    TimeDistribution {}
}
