//! PCAP generation process management.
//!
//! This module handles starting generation threads and polling for updates.

use super::core::generate;
use crate::run::state::RunTabState;
use crate::shared::config::state::ConfigFileState;
use eframe::egui;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::channel;

/// Start the PCAP generation process in a background thread.
///
/// Creates channels for progress updates, PCAP data, throughput metrics, and errors.
/// The generation runs asynchronously (native thread or WASM future).
pub fn start_generation(
    state: &mut RunTabState,
    configuration_file_state: &ConfigFileState,
    models: fosr_lib::models::ArcModels,
    ctx: &egui::Context,
) {
    // Reset state
    state.generation.progress = 0.0;
    state.generation.error = None;
    state.generation.cancelled = Arc::new(AtomicBool::new(false));

    let (progress_sender, progress_receiver) = channel();
    state.generation.progress_receiver = Some(progress_receiver);

    let (pcap_sender, pcap_receiver) = channel();
    state.generation.pcap_receiver = Some(pcap_receiver);

    let (throughput_sender, throughput_receiver) = channel();
    state.generation.throughput_receiver = Some(throughput_receiver);
    state.generation.throughput = None;

    let (error_sender, error_receiver) = channel();
    state.generation.error_receiver = Some(error_receiver);

    let params = PcapGenerationParams::from_state(state, configuration_file_state);
    let cancelled = state.generation.cancelled.clone();
    let ctx = ctx.clone();


    spawn_generation_task(
        models,
        params,
        progress_sender,
        pcap_sender,
        throughput_sender,
        error_sender,
        cancelled,
        ctx,
    );
}

/// Generation parameters extracted from UI state.
struct PcapGenerationParams {
    seed: Option<u64>,
    order_pcap: bool,
    start_time: Option<String>,
    duration: String,
    taint: bool,
    timezone: Option<String>,
}

impl PcapGenerationParams {
    /// Extracts parameters from the UI state and config file.
    fn from_state(state: &RunTabState, config_state: &ConfigFileState) -> Self {
        let seed = if state.generation.use_seed {
            parse_seed(&state.generation.seed_input)
        } else {
            None
        };
        let start_time = if state.generation.use_current_time {
            None
        } else {
            Some(format!(
                "{}T{}Z",
                state.generation.start_date.format("%Y-%m-%d"),
                state.generation.start_time.format("%H:%M:%S")
            ))
        };
        let timezone = if state.generation.timezone_input.is_empty() {
            None
        } else {
            Some(state.generation.timezone_input.clone())
        };
        // Prefer in-memory config content (reflects edits from Configuration tab)
        // over re-reading the file from disk
        // let config_content = config_state.config_file_content.clone();

        Self {
            seed,
            order_pcap: state.generation.order_pcap,
            start_time,
            duration: state.generation.duration_str.clone(),
            taint: state.generation.taint,
            timezone,
            // config_content,
        }
    }
}

/// Parses a seed input string into an optional u64.
///
/// - Empty input returns `None` (random seed).
/// - A valid u64 literal is used directly.
/// - Any other text is hashed using SHA-256 to produce a deterministic u64.
fn parse_seed(input: &str) -> Option<u64> {
    let s = input.trim();
    if s.is_empty() {
        return None;
    }
    if let Ok(n) = s.parse::<u64>() {
        return Some(n);
    }
    let hash = Sha256::digest(s.as_bytes());
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&hash[0..8]);
    Some(u64::from_be_bytes(bytes))
}

/// Spawns the generation task on the appropriate platform (WASM future or native thread).
fn spawn_generation_task(
    models: fosr_lib::models::ArcModels,
    params: PcapGenerationParams,
    progress_sender: std::sync::mpsc::Sender<f32>,
    pcap_sender: std::sync::mpsc::Sender<Vec<u8>>,
    throughput_sender: std::sync::mpsc::Sender<String>,
    error_sender: std::sync::mpsc::Sender<String>,
    cancelled: Arc<AtomicBool>,
    ctx: egui::Context,
) {
    
    let task = move || {
        let result = generate(
            models,
            params.seed,
            // params.config_content,
            params.order_pcap,
            params.start_time,
            params.duration,
            params.taint,
            params.timezone,
            Some(progress_sender),
            Some(pcap_sender),
            Some(throughput_sender),
            cancelled,
        );
        if let Err(e) = result {
            log::error!("Generation failed: {}", e);
            let _ = error_sender.send(e);
        }
        ctx.request_repaint();
    };

    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_futures::spawn_local(async move { task() });

    #[cfg(not(target_arch = "wasm32"))]
    std::thread::spawn(task);
}

/// Poll generation receivers for progress, PCAP data, throughput, and errors.
///
/// Should be called every frame to update the UI with generation status.
pub fn poll_generation_receivers(ctx: &egui::Context, state: &mut RunTabState) {
    poll_progress(ctx, state);
    poll_pcap(state);
    poll_throughput(state);
    poll_error(state);
}

/// Polls for progress updates and requests repaints while generating.
fn poll_progress(ctx: &egui::Context, state: &mut RunTabState) {
    if let Some(receiver) = &state.generation.progress_receiver {
        // Request repaint to keep polling while generating
        ctx.request_repaint();
        if let Ok(progress) = receiver.try_recv() {
            state.generation.progress = progress;
            if progress == 1.0 {
                state.generation.progress_receiver = None;
            }
        }
    }
}

/// Polls for PCAP data when generation completes.
fn poll_pcap(state: &mut RunTabState) {
    if let Some(receiver) = &state.generation.pcap_receiver
        && let Ok(pcap_bytes) = receiver.try_recv()
    {
        state.generation.pcap_bytes = Some(pcap_bytes);
    }
}

/// Polls for throughput metrics when generation completes.
fn poll_throughput(state: &mut RunTabState) {
    if let Some(receiver) = &state.generation.throughput_receiver
        && let Ok(throughput) = receiver.try_recv()
    {
        state.generation.throughput = Some(throughput);
        state.generation.throughput_receiver = None;
    }
}

/// Polls for error messages from the generation thread.
fn poll_error(state: &mut RunTabState) {
    if let Some(receiver) = &state.generation.error_receiver
        && let Ok(error) = receiver.try_recv()
    {
        state.generation.error = Some(error);
        state.generation.error_receiver = None;
        state.generation.progress_receiver = None; // Stop progress polling
    }
}
