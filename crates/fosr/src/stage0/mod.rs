use crate::structs::*;
use crate::ui::Stats;

use chrono::{DateTime, Timelike};
use crossbeam_channel::Sender;
use rand_core::*;
use rand_distr::Distribution;
use rand_distr::Poisson;
use rand_distr::Uniform;
use rand_pcg::Pcg32;
use serde::Deserialize;
use std::fs::File;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use chrono::FixedOffset;

const WINDOW_WIDTH_IN_SECS: u64 = 5;

/// Stage 0: generate timestamps.
/// Generate a throughput according to some distribution and never stops. It always prepares the next windows (i.e., not
/// the one being sent)
pub trait Stage0:
    Iterator<Item = SeededData<Duration>> + Clone + std::marker::Send + 'static
{
    fn get_initial_ts(&self) -> Duration;
}

/// The generator generates timestamp from bins
/// In net_injection mode, it trickles the generation
#[derive(Debug, Clone)]
pub struct BinBasedGenerator {
    next_ts: Duration, // the start of the *next* generation window
    initial_ts: Duration,
    remaining_flows: u64,
    lambdas: Vec<f64>,
    current_distrib: Poisson<f64>,
    total_flow_count: u64,
    time_distrib: Uniform<u64>,
    window_rng: Pcg32,
    flow_rng: Pcg32,
    net_injection: bool,
    remaining_windows: Option<u64>,
    tz_offset: FixedOffset,
}

impl Stage0 for BinBasedGenerator {
    fn get_initial_ts(&self) -> Duration {
        self.initial_ts
    }
}

impl Iterator for BinBasedGenerator {
    type Item = SeededData<Duration>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.remaining_flows == 0 {
            if self.net_injection {
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

            let ok = self.start_new_window();
            if !ok {
                log::info!("{} generated flows", self.total_flow_count);
                return None;
            }
        }
        self.remaining_flows -= 1;
        self.total_flow_count += 1;
        Some(SeededData {
            seed: self.flow_rng.next_u64(),
            data: Duration::from_millis(self.time_distrib.sample(&mut self.flow_rng.clone())),
        })
    }
}

fn get_poisson(lambdas: &Vec<f64>, tz_offset: FixedOffset, ts: Duration) -> Poisson<f64> {
    let secs = DateTime::from_timestamp_secs(ts.as_secs() as i64).unwrap().with_timezone(&tz_offset).time()
        .num_seconds_from_midnight();
    // log::info!("Hours since midnight: {}", secs/3600);
    let secs_per_bin = (60 * 60 * 24 / lambdas.len()) as u32;
    let index = ((secs / secs_per_bin) as usize).min(lambdas.len() - 1);
    // log::info!("Poisson’ lambda: {}", lambdas[index]);
    Poisson::new(lambdas[index]).unwrap()
}

/// Compute the parameters of the Poisson distribution from the bins
/// If "flow_per_day" is None, then simply reuse the values of the bins
/// Otherwise, normalize the bins so their sum is "flow_per_day"
fn get_lambdas(flow_per_day: Option<u64>, bins: TimeBins) -> Vec<f64> {
    let bin_count: f64 = bins.bins.len() as f64;
    let window_per_bin: f64 = 60. * 60. * 24. / (WINDOW_WIDTH_IN_SECS as f64) / bin_count;
    match flow_per_day {
        Some(flow_per_day) => {
            let sum: f64 = bins.bins.iter().sum::<u64>() as f64;
            // Lambda is equal to the expected value of the Poisson distribution
            // First, we normalize the bin so the sum of all bins is flow_per_day
            // Then, we divide by the number of windows in one bin
            bins.bins
                .into_iter()
                .map(|val| (val as f64) / sum * (flow_per_day as f64) / window_per_bin)
                .collect()
        }
        None => bins
            .bins
            .into_iter()
            .map(|val| (val as f64) / window_per_bin)
            .collect(),
    }
}

impl BinBasedGenerator {
    pub fn new(
        seed: Option<u64>,
        net_injection: bool,
        flow_per_day: Option<u64>,
        bins: TimeBins,
        initial_ts: Duration,
        total_duration: Option<Duration>,
        tz_offset: FixedOffset,
    ) -> Self {
        let next_ts = initial_ts;
        let time_distrib = Uniform::new(
            next_ts.as_millis() as u64,
            next_ts.as_millis() as u64 + 1000 * WINDOW_WIDTH_IN_SECS,
        )
        .unwrap();
        let window_rng = match seed {
            Some(s) => Pcg32::seed_from_u64(s),
            None => Pcg32::from_os_rng(),
        };
        let remaining_windows = total_duration.map(|d| {
            d.div_duration_f32(Duration::from_secs(WINDOW_WIDTH_IN_SECS))
                .ceil() as u64
        });

        let lambdas = get_lambdas(flow_per_day, bins);

        let mut generator = BinBasedGenerator {
            net_injection,
            initial_ts,
            next_ts,
            lambdas,
            current_distrib: Poisson::new(1.).unwrap(), // it will be overwritten
            remaining_flows: 0,
            total_flow_count: 0,
            window_rng,
            flow_rng: Pcg32::seed_from_u64(0), // it will be overwritten
            time_distrib,
            remaining_windows,
            tz_offset,
        };
        generator.start_new_window();
        generator
    }

    pub fn new_for_injection(
        seed: Option<u64>,
        total_duration: Option<Duration>,
        flow_per_day: Option<u64>,
        bins: TimeBins,
        deterministic: bool,
    ) -> Self {
        let current_date = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let window_count_since_unix_epoch =
            ((current_date + Duration::from_secs(WINDOW_WIDTH_IN_SECS)).as_secs_f64()
                / (WINDOW_WIDTH_IN_SECS as f64))
                .ceil() as u64;
        let mut window_rng = match seed {
            Some(s) => Pcg32::seed_from_u64(s),
            None => Pcg32::new(0xcafef00dd15ea5e5, 0xa02bdbf7bb3c0a7), // default values from the doc
        };
        if !deterministic {
            // each process should use the same rng at the same time !
            // 2 for a next_u64 call
            window_rng.advance(2 * window_count_since_unix_epoch);
        }
        let next_ts = Duration::from_secs(window_count_since_unix_epoch * WINDOW_WIDTH_IN_SECS);
        let time_distrib = Uniform::new(
            next_ts.as_millis() as u64,
            next_ts.as_millis() as u64 + 1000 * WINDOW_WIDTH_IN_SECS,
        )
        .unwrap();
        let remaining_windows = total_duration.map(|d| {
            d.div_duration_f32(Duration::from_secs(WINDOW_WIDTH_IN_SECS))
                .ceil() as u64
        });
        let lambdas = get_lambdas(flow_per_day, bins);

        let mut generator = BinBasedGenerator {
            net_injection: true,
            initial_ts: next_ts,
            next_ts,
            lambdas,
            current_distrib: Poisson::new(1.).unwrap(), // it will be overwritten
            remaining_flows: 0,
            total_flow_count: 0,
            window_rng,
            flow_rng: Pcg32::seed_from_u64(0), // it will be overwritten
            time_distrib,
            remaining_windows,
            tz_offset: *chrono::Local::now().fixed_offset().offset(), // use local timezone
        };
        generator.start_new_window();
        generator
    }

    /// Start a new window
    /// Returns "false" it’s not possible
    fn start_new_window(&mut self) -> bool {
        // log::info!("New window!");
        self.flow_rng = Pcg32::seed_from_u64(self.window_rng.next_u64());
        if let Some(ref mut r) = self.remaining_windows {
            *r -= 1;
            if *r == 0 {
                return false;
            }
        }

        self.current_distrib = get_poisson(&self.lambdas, self.tz_offset, self.next_ts);
        self.remaining_flows = self.current_distrib.sample(&mut self.flow_rng.clone()) as u64;
        // log::info!("{}", self.remaining_flows);
        self.time_distrib = Uniform::new(
            self.next_ts.as_millis() as u64,
            self.next_ts.as_millis() as u64 + 1000 * WINDOW_WIDTH_IN_SECS,
        )
        .unwrap();
        self.next_ts += Duration::from_secs(WINDOW_WIDTH_IN_SECS);
        return true;
    }
}

pub struct TimeBins {
    bins: Vec<u64>,
}

impl Default for TimeBins {
    fn default() -> Self {
        if cfg!(debug_assertions) {
            TimeBins::from_str(include_str!("../../default_models/time_bins.json")).unwrap()
        } else {
            TimeBins::from_str(
                &String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                    "default_models/time_bins.json",
                    19
                ))
                .unwrap(),
            )
            .unwrap()
        }
    }
}

impl TimeBins {
    pub fn from_file(filename: &str) -> std::io::Result<Self> {
        let f = File::open(filename)?;
        let config: Config = serde_json::from_reader(f)?;
        Ok(TimeBins {
            bins: config.histogram,
        })
    }

    pub fn from_str(string: &str) -> std::io::Result<Self> {
        let config: Config = serde_json::from_str(string)?;
        Ok(TimeBins {
            bins: config.histogram,
        })
    }
}

#[derive(Deserialize, Debug, Clone)]
#[allow(unused)]
struct Config {
    histogram: Vec<u64>,
    metadata: Metadata,
}

#[derive(Deserialize, Debug, Clone)]
#[allow(unused)]
struct Metadata {
    creation_time: String,
    input_file: String,
}

pub fn run(
    generator: impl Stage0,
    tx_s0: Sender<SeededData<Duration>>,
    stats: Arc<Stats>,
) -> Result<(), Box<dyn std::error::Error>> {
    log::trace!("Start S0");
    let initial_ts = generator.get_initial_ts();
    for ts in generator {
        if stats.should_stop() {
            break;
        }
        stats.set_current_duration(ts.data.as_secs() - initial_ts.as_secs() + WINDOW_WIDTH_IN_SECS); // this hack (adding WINDOW_WIDTH_IN_SECS) is just a way to be sure to reach the duration target for the progress bar
        // log::trace!("S0 generates {ts:?}");
        tx_s0.send(ts)?;
    }
    log::trace!("S0 stops");
    Ok(())
}
