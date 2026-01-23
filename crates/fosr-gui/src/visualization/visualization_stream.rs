//! Flow streaming engine for real-time visualization
//!
//! This module provides a streaming generator that runs Stage 0 (time generation)
//! and Stage 1 (flow generation) to produce flow events for the visualization tab.
//!
//! Flows are emitted based on their timestamps relative to visualization start,
//! allowing multiple flows to be displayed in parallel.

use chrono::{DateTime, Offset, TimeZone};
use fosr_lib::{models, stage0, stage1::bayesian_networks::BNGenerator, stage1::Stage1, L7Proto};
use std::collections::BinaryHeap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use web_time::{Instant, SystemTime, UNIX_EPOCH};

/// A flow event (subset of FlowData)
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowEvent {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub protocol: L7Proto,
    #[allow(dead_code)] // Kept for possible future UI features
    pub timestamp: Duration,
}

/// A flow event with its scheduled display time
#[derive(Eq)]
struct ScheduledFlow {
    event: FlowEvent,
    /// Timestamp relative to generation start (for scheduling)
    scheduled_time: Duration,
}

impl PartialEq for ScheduledFlow {
    fn eq(&self, other: &Self) -> bool {
        self.scheduled_time == other.scheduled_time
    }
}


impl PartialOrd for ScheduledFlow {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ScheduledFlow {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Reverse ordering for min-heap behavior (earliest first)
        other.scheduled_time.cmp(&self.scheduled_time)
    }
}

/// Flow streamer that continuously generates flow events
pub struct FlowStreamer {
    s0: stage0::BinBasedGenerator,
    s1: BNGenerator,
    sender: Sender<FlowEvent>,
    running: Arc<AtomicBool>,
    /// The initial timestamp from Stage 0 (for calculating relative times)
    initial_timestamp: Duration,
    /// Speed multiplier (1.0 = real-time) - shared for runtime updates
    speed: Arc<RwLock<f32>>,
}

impl FlowStreamer {
    /// Create a new flow streamer
    /// If config_content is None, uses the default BN model without any config applied
    /// If config_content is Some, applies the config to remap IPs
    /// Speed controls how fast flows are emitted (1.0 = real-time) - can be updated at runtime
    pub fn new(
        config_content: Option<&str>,
        speed: Arc<RwLock<f32>>,
        sender: Sender<FlowEvent>,
    ) -> Result<Self, String> {
        // Load models
        let source = models::ModelsSource::Legacy;
        let mut model = models::Models::from_source(source)
            .map_err(|e| format!("Failed to load models: {}", e))?;

        // Only apply config if provided
        if let Some(config) = config_content {
            model = model
                .with_string_config(config)
                .map_err(|e| format!("Failed to apply config: {}", e))?;
            log::info!("FlowStreamer: config applied");
        } else {
            log::info!("FlowStreamer: using default BN model (no config)");
        }

        let _automata_library = Arc::new(model.automata);
        let bn = Arc::new(model.bn);

        // Get initial timestamp (current time)
        let initial_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("Failed to get time: {}", e))?;

        // Get local timezone
        // TODO: use the value from the generation tab?
        // TODO: extract the logic in utils to share it with generation_core
        let tz_offset = {
            let date = DateTime::from_timestamp(initial_ts.as_secs() as i64, 0)
                .unwrap()
                .naive_utc();
            let tz = chrono::Local::now()
                .timezone()
                .offset_from_local_datetime(&date)
                .single()
                .expect("Ambiguous local date from timestamp")
                .fix();
            log::info!("Using local timezone (UTC{tz})");
            tz
        };

        // Create Stage 0 generator
        let s0 = stage0::BinBasedGenerator::new(
            None, // Random seed
            false,
            None,
            model.time_bins,
            initial_ts,
            None, // Infinite duration
            tz_offset,
        );

        // Create Stage 1 generator
        let s1 = BNGenerator::new(bn, false);

        Ok(Self {
            s0,
            s1,
            sender,
            running: Arc::new(AtomicBool::new(false)),
            initial_timestamp: initial_ts,
            speed,
        })
    }

    /// Start streaming flows in the background
    pub fn start(&self) {
        self.running.store(true, Ordering::SeqCst);
        let sender = self.sender.clone();
        let running = self.running.clone();
        let s0 = self.s0.clone();
        let s1 = self.s1.clone();
        let initial_timestamp = self.initial_timestamp;
        let speed = self.speed.clone();

        #[cfg(not(target_arch = "wasm32"))]
        std::thread::spawn(move || {
            Self::streaming_loop(s0, s1, sender, running, initial_timestamp, speed);
        });

        #[cfg(target_arch = "wasm32")]
        wasm_bindgen_futures::spawn_local(async move {
            Self::streaming_loop_wasm(s0, s1, sender, running, initial_timestamp, speed).await;
        });
    }

    /// Stop streaming flows
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn streaming_loop(
        mut s0: stage0::BinBasedGenerator,
        s1: BNGenerator,
        sender: Sender<FlowEvent>,
        running: Arc<AtomicBool>,
        initial_timestamp: Duration,
        speed: Arc<RwLock<f32>>,
    ) {
        // Use a binary heap to generate flows (timestamp ordered) in the correct order
        let mut pending_flows: BinaryHeap<ScheduledFlow> = BinaryHeap::new();
        let mut flow_count = 0;
        let mut last_generation = Instant::now();

        // Buffer size: generate flows up to this much ahead of current time
        // This avoids overloading the CPU by continuously generating flows
        let buffer_ahead = Duration::from_secs(5);
        // How often to check for flows to emit
        let check_interval = Duration::from_millis(50);

        // Track virtual time by integrating speed changes
        //
        // Why do we need virtual time? Because when we change the speed value at runtime,
        // the elapsed time so far should not be scaled, only the time that elapses from the moment
        // the speed has changed. If we scale the whole elapsed time, and reduce the speed, we will
        // "go back in time" (e.g., elapsed time is 20s, we reduce speed from 1.0 to 0.5, elapsed time
        // would become 10s. We would need to wait 10s before new packets are emitted again).
        let mut virtual_elapsed = Duration::ZERO;

        let mut last_loop_time = Instant::now();

        log::info!(
            "Flow streaming loop started (timestamp-based, speed: {}x)",
            *speed.read().unwrap()
        );

        while running.load(Ordering::SeqCst) {
            let now = Instant::now();
            let delta = now.duration_since(last_loop_time);
            last_loop_time = now;

            // Integrate speed over time to avoid discontinuities (see previous comment)
            let speed = *speed.read().unwrap();
            let virtual_delta = Duration::from_secs_f64(delta.as_secs_f64() * speed as f64);
            virtual_elapsed += virtual_delta;

            // Generate more flows if buffer is running low
            let buffer_target = virtual_elapsed + buffer_ahead;
            while pending_flows
                // since we use a binary heap, we get the flow with the biggest timestamp
                .peek()
                // if the heap is empty, `.peek()` returns None, and `.map_or()` returns true
                .map_or(true, |f| f.scheduled_time < buffer_target)
            {
                // Limit generation rate to avoid CPU spinning
                if last_generation.elapsed() < Duration::from_millis(100) && !pending_flows.is_empty()
                {
                    break;
                }

                if let Some(timestamp) = s0.next() {
                    if let Ok(flows) = s1.generate_flows(timestamp) {
                        for seeded_flow in flows {
                            let flow_data = seeded_flow.data.get_data();

                            // Calculate scheduled time relative to start
                            let flow_timestamp = flow_data.timestamp;
                            let scheduled_time = if flow_timestamp >= initial_timestamp {
                                flow_timestamp - initial_timestamp
                            } else {
                                Duration::ZERO
                            };

                            let event = FlowEvent {
                                src_ip: flow_data.src_ip,
                                dst_ip: flow_data.dst_ip,
                                protocol: flow_data.l7_proto,
                                timestamp: flow_timestamp,
                            };

                            pending_flows.push(ScheduledFlow {
                                event,
                                scheduled_time,
                            });

                            flow_count += 1;
                        }
                    }
                } else {
                    // No more timestamps available
                    break;
                }

                last_generation = Instant::now();

                // Check if we should stop
                if !running.load(Ordering::SeqCst) {
                    break;
                }
            }


            // Emit flows whose scheduled time has passed (in virtual time)
            while let Some(scheduled) = pending_flows.peek() {
                if scheduled.scheduled_time <= virtual_elapsed {
                    let scheduled = pending_flows.pop().unwrap();
                    log::debug!(
                        "Emitting flow #{}: {} -> {} ({:?}) at virtual {:?}",
                        flow_count,
                        scheduled.event.src_ip,
                        scheduled.event.dst_ip,
                        scheduled.event.protocol,
                        virtual_elapsed
                    );

                    if let Err(e) = sender.send(scheduled.event) {
                        log::error!("Failed to send flow event: {}", e);
                        break;
                    }
                } else {
                    break;
                }
            }

            // Sleep until next check
            std::thread::sleep(check_interval);
        }

        log::info!(
            "Flow streaming loop stopped ({} flows generated, {} pending)",
            flow_count,
            pending_flows.len()
        );
    }

    // TODO: check if this works properly and update comments to match with native arch
    #[cfg(target_arch = "wasm32")]
    async fn streaming_loop_wasm(
        mut s0: stage0::BinBasedGenerator,
        s1: BNGenerator,
        sender: Sender<FlowEvent>,
        running: Arc<AtomicBool>,
        initial_timestamp: Duration,
        speed: Arc<RwLock<f32>>,
    ) {
        let mut pending_flows: BinaryHeap<ScheduledFlow> = BinaryHeap::new();
        let buffer_ahead = Duration::from_secs(5);
        let check_interval = Duration::from_millis(50);

        // Track virtual time by integrating speed changes
        let mut virtual_elapsed = Duration::ZERO;
        let mut last_loop_time = Instant::now();

        while running.load(Ordering::SeqCst) {
            let now = Instant::now();
            let delta = now.duration_since(last_loop_time);
            last_loop_time = now;

            // Integrate speed over time to avoid discontinuities
            let speed = *speed.read().unwrap();
            let virtual_delta = Duration::from_secs_f64(delta.as_secs_f64() * speed as f64);
            virtual_elapsed += virtual_delta;

            // Generate more flows if buffer is running low
            let buffer_target = virtual_elapsed + buffer_ahead;
            let mut generated_this_cycle = 0;

            while pending_flows
                .peek()
                .map_or(true, |f| f.scheduled_time < buffer_target)
                && generated_this_cycle < 10
            {
                if let Some(timestamp) = s0.next() {
                    if let Ok(flows) = s1.generate_flows(timestamp) {
                        for seeded_flow in flows {
                            let flow_data = seeded_flow.data.get_data();

                            let flow_timestamp = flow_data.timestamp;
                            let scheduled_time = if flow_timestamp >= initial_timestamp {
                                flow_timestamp - initial_timestamp
                            } else {
                                Duration::ZERO
                            };

                            let event = FlowEvent {
                                src_ip: flow_data.src_ip,
                                dst_ip: flow_data.dst_ip,
                                protocol: flow_data.l7_proto,
                                timestamp: flow_timestamp,
                            };

                            pending_flows.push(ScheduledFlow {
                                event,
                                scheduled_time,
                            });
                        }
                    }
                    generated_this_cycle += 1;
                } else {
                    break;
                }
            }

            // Emit flows whose scheduled time has passed
            while let Some(scheduled) = pending_flows.peek() {
                if scheduled.scheduled_time <= virtual_elapsed {
                    let scheduled = pending_flows.pop().unwrap();
                    let _ = sender.send(scheduled.event);
                } else {
                    break;
                }
            }

            web_time::sleep(check_interval).await;
        }
    }
}
