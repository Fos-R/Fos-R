use crate::structs::*;
use crate::ui::Stats;

use crossbeam_channel::Sender;
use rand_core::*;
use rand_distr::Distribution;
use rand_distr::Uniform;
use rand_pcg::Pcg32;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const WINDOW_WIDTH_IN_SECS: u64 = 5;

/// Stage 0: generate timestamps.
/// Generate a uniform throughput and never stops. It always prepares the next windows (i.e., not
/// the one being sent)
pub trait Stage0:
    Iterator<Item = SeededData<Duration>> + Clone + std::marker::Send + 'static
{
}

/// The generator generates timestamp uniformily without any seasonability (day/night cycle, etc.)
/// In online mode, it trickles the generation
#[derive(Debug, Clone)]
pub struct UniformGenerator {
    next_ts: Duration, // the start of the S0 generation window = the end of the sending window
    flows_per_window: u64,
    remaining: u64,
    total_flow_count: u64,
    time_distrib: Uniform<u64>,
    rng: Pcg32,
    aux_rng: Pcg32,
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
                    thread::sleep(
                        self.next_ts
                            .saturating_sub(SystemTime::now().duration_since(UNIX_EPOCH).unwrap()),
                    );
                }
            }
            self.remaining = self.flows_per_window;
            self.next_ts += Duration::from_secs(WINDOW_WIDTH_IN_SECS);
            self.time_distrib = Uniform::new(
                self.next_ts.as_millis() as u64,
                self.next_ts.as_millis() as u64 + 1000 * WINDOW_WIDTH_IN_SECS,
            );
        }
        self.remaining -= 1;
        self.total_flow_count += 1;
        // since we cannot know how many rng calls sample will make, better use an auxiliary rng
        self.aux_rng.clone_from(&self.rng);
        // advance before sampling so we don’t reuse the values used by time_distrib
        // 8 should be plenty
        self.rng.advance(8);
        Some(SeededData {
            seed: self.rng.next_u64(),
            data: Duration::from_millis(self.time_distrib.sample(&mut self.aux_rng.clone())),
        })
    }
}

impl UniformGenerator {
    pub fn new(
        seed: Option<u64>,
        online: bool,
        flow_per_second: u64,
        initial_ts: Duration,
    ) -> Self {
        let flows_per_window = flow_per_second * WINDOW_WIDTH_IN_SECS;
        let next_ts = initial_ts;
        let time_distrib = Uniform::new(
            next_ts.as_millis() as u64,
            next_ts.as_millis() as u64 + 1000 * WINDOW_WIDTH_IN_SECS,
        );
        let rng = match seed {
            Some(s) => Pcg32::seed_from_u64(s),
            None => Pcg32::from_entropy(),
        };
        let aux_rng = rng.clone();
        UniformGenerator {
            online,
            next_ts,
            total_flow_count: 0,
            remaining: flows_per_window,
            flows_per_window,
            rng,
            aux_rng,
            time_distrib,
        }
    }

    pub fn new_for_honeypot(
        seed: Option<u64>,
        current_date: Duration,
        flow_per_second: u64,
    ) -> Self {
        let flows_per_window = flow_per_second * WINDOW_WIDTH_IN_SECS;
        let window_count_since_unix_epoch =
            ((current_date + Duration::from_secs(WINDOW_WIDTH_IN_SECS)).as_secs_f64()
                / (WINDOW_WIDTH_IN_SECS as f64))
                .ceil() as u64;
        let mut rng = match seed {
            Some(s) => Pcg32::seed_from_u64(s),
            None => Pcg32::new(0xcafef00dd15ea5e5, 0xa02bdbf7bb3c0a7), // default values
        };
        rng.advance(10 * window_count_since_unix_epoch * flows_per_window);
        // 10 = 8 by advancing + 2 for a next_u64 call
        let next_ts = Duration::from_secs(window_count_since_unix_epoch * WINDOW_WIDTH_IN_SECS);
        let time_distrib = Uniform::new(
            next_ts.as_millis() as u64,
            next_ts.as_millis() as u64 + 1000 * WINDOW_WIDTH_IN_SECS,
        );
        let aux_rng = rng.clone();
        UniformGenerator {
            online: true,
            next_ts,
            total_flow_count: 0,
            remaining: flows_per_window,
            flows_per_window,
            rng,
            aux_rng,
            time_distrib,
        }
    }
}

pub fn run(
    generator: impl Stage0,
    tx_s0: Sender<SeededData<Duration>>,
    stats: Arc<Stats>,
) -> Result<(), Box<dyn std::error::Error>> {
    log::trace!("Start S0");
    for ts in generator {
        if stats.should_stop() {
            break;
        }
        log::trace!("S0 generates {ts:?}");
        tx_s0.send(ts)?;
    }
    log::trace!("S0 stops");
    Ok(())
}
