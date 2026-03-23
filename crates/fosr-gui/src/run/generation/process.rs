//! PCAP generation process management.
//!
//! This module handles starting generation threads and polling for updates.

use super::core::generate;
use crate::run::state::RunTabState;
use crate::shared::configuration_file::ConfigurationFileState;
use eframe::egui;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::channel;

/// Start the PCAP generation process in a background thread.
///
/// Creates channels for progress updates, PCAP data, and throughput metrics.
/// The generation runs asynchronously (native thread or WASM future).
pub fn start_generation(
    state: &mut RunTabState,
    configuration_file_state: &ConfigurationFileState,
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

    let seed = if state.generation.use_seed {
        state.generation.seed_input.parse::<u64>().ok()
    } else {
        None
    };
    let order_pcap = state.generation.order_pcap;
    let start_time = if state.generation.use_current_time {
        None
    } else {
        Some(format!(
            "{}T{}Z",
            state.generation.start_date.format("%Y-%m-%d"),
            state.generation.start_hour.format("%H:%M:%S")
        ))
    };
    let duration = state.generation.duration_str.clone();
    let taint = state.generation.taint;
    let timezone = if state.generation.timezone_input.is_empty() {
        None
    } else {
        Some(state.generation.timezone_input.clone())
    };
    let ctx = ctx.clone();
    let cancelled = state.generation.cancelled.clone();
    // Prefer in-memory config content (reflects edits from Configuration tab)
    // over re-reading the file from disk
    let config_content = configuration_file_state.config_file_content.clone();

    #[cfg(target_arch = "wasm32")]
    {
        wasm_bindgen_futures::spawn_local(async move {
            generate(
                seed,
                config_content,
                order_pcap,
                start_time,
                duration,
                taint,
                timezone,
                Some(progress_sender),
                Some(pcap_sender),
                Some(throughput_sender),
                cancelled,
            );
            ctx.request_repaint();
        });
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        std::thread::spawn(move || {
            generate(
                seed,
                config_content,
                order_pcap,
                start_time,
                duration,
                taint,
                timezone,
                Some(progress_sender),
                Some(pcap_sender),
                Some(throughput_sender),
                cancelled,
            );
            ctx.request_repaint();
        });
    }
}

/// Poll generation receivers for progress, PCAP data, and throughput.
///
/// Should be called every frame to update the UI with generation status.
pub fn poll_generation_receivers(ctx: &egui::Context, state: &mut RunTabState) {
    // Poll progress receiver
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

    // Poll pcap receiver
    if let Some(receiver) = &state.generation.pcap_receiver {
        if let Ok(pcap_bytes) = receiver.try_recv() {
            state.generation.pcap_bytes = Some(pcap_bytes);
        }
    }

    // Poll throughput receiver
    if let Some(receiver) = &state.generation.throughput_receiver {
        if let Ok(throughput) = receiver.try_recv() {
            state.generation.throughput = Some(throughput);
            state.generation.throughput_receiver = None;
        }
    }
}
