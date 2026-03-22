use super::run_state::RunState;
use crate::generation::generation_core::generate;
use crate::generation::generation_ui_components::{show_field_error, timezone_picker};
use crate::generation::generation_validation::{
    first_invalid_param, validate_duration, validate_optional_u64, validate_timezone,
};
#[cfg(not(target_arch = "wasm32"))]
use crate::generation::generation_wireshark::open_in_wireshark;
use crate::shared::configuration_file::{ConfigurationFileState, load_config_file_contents};
#[cfg(not(target_arch = "wasm32"))]
use crate::shared::file_io::save_file_desktop;
#[cfg(target_arch = "wasm32")]
use crate::shared::file_io::save_file_wasm;
use crate::shared::ui_utils::info_icon;
use crate::timepicker::TimePickerButton;
use crate::visualization::visualization_modal::{process_graph_events, render_node_info_modal};
use crate::visualization::visualization_overlays::{
    render_overlay_buttons, render_overlay_edge_legend, render_overlay_node_legend,
    render_overlay_stats,
};
use crate::visualization::visualization_screenshot::handle_screenshot_export;
use crate::visualization::visualization_shapes::{NetworkEdgeShape, NetworkNodeShape};
use crate::visualization::visualization_state::{
    ActiveLink, EdgeData, EdgeState, ExportState, INTERNET_IP, LinkDirection, NodeData,
    VisualizationTabState,
};
use crate::visualization::visualization_stream::FlowEvent;
use chrono::{Datelike, Local, TimeZone};
use chrono_tz::Tz;
use eframe::egui::{self, Widget};
use egui_extras::DatePickerButton;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::channel;

pub fn show_run_tab_content(
    ui: &mut egui::Ui,
    state: &mut RunState,
    configuration_file_state: &mut ConfigurationFileState,
) {
    // Load config file contents if a file is selected but content not yet loaded
    load_config_file_contents(configuration_file_state);

    // Handle config changes for visualization
    handle_config_changes(&mut state.visualization, configuration_file_state);

    // Auto-start visualization with delay (allows UI to render first)
    if let Some(countdown) = state.visualization.auto_start_countdown {
        if countdown > 0 {
            state.visualization.auto_start_countdown = Some(countdown - 1);
        } else if !state.visualization.visualization_running {
            let config = state.visualization.config_content.clone();
            let speed = state.visualization.speed.clone();
            if let Err(e) = state
                .visualization
                .start_visualization(config.as_deref(), speed, true)
            {
                log::error!("Failed to auto-start visualization: {}", e);
            }
            state.visualization.auto_start_countdown = None;
        }
    }

    // Handle delayed fit-to-screen (after panel toggle or on initial load)
    if let Some(countdown) = state.visualization.delayed_fit_countdown {
        if countdown > 0 {
            state.visualization.delayed_fit_countdown = Some(countdown - 1);
        } else {
            state.visualization.reset_view_requested = true;
            state.visualization.delayed_fit_countdown = None;
        }
    }

    // Process incoming flow events
    process_flow_events(&mut state.visualization);

    // Update active links (remove expired ones)
    update_active_links(&mut state.visualization);

    // Update graph edges based on active links
    update_graph_edges(&mut state.visualization);

    // Poll generation receivers (must be done before rendering UI)
    poll_generation_receivers(ui.ctx(), state);

    // Bottom panel (action bar + expandable options)
    show_bottom_panel(ui.ctx(), state, configuration_file_state);

    // Render the graph view
    render_graph_view(ui, state);

    // Process node click events and render info modal
    process_graph_events(&mut state.visualization, configuration_file_state);
    render_node_info_modal(ui.ctx(), &mut state.visualization, configuration_file_state);
}

/// Handle configuration file changes
fn handle_config_changes(
    state: &mut VisualizationTabState,
    configuration_file_state: &ConfigurationFileState,
) {
    // Check if config was removed or is empty
    let config_is_empty = configuration_file_state
        .config_file_content
        .as_ref()
        .map(|c| c.trim().is_empty())
        .unwrap_or(true);

    let was_config_removed =
        state.config_content.is_some() && configuration_file_state.config_file_content.is_none();

    // Only reset if we previously had a config (avoid resetting every frame when starting empty)
    let should_reset = was_config_removed || (config_is_empty && state.config_content.is_some());

    if should_reset {
        // Stop visualization if running, then reset to default
        if state.visualization_running {
            state.stop_visualization();
        }
        state.config_content = None;
        *state = VisualizationTabState::default();
        state.reset_view_requested = true;
        log::warn!("Config removed or empty, visualization reset to default");
        return;
    }

    // If config is empty and we have no config loaded, nothing to do
    if config_is_empty && state.config_content.is_none() {
        return;
    }

    // Check if config content has changed
    let needs_update = match (
        &state.config_content,
        &configuration_file_state.config_file_content,
    ) {
        (Some(current), Some(new)) => current != new,
        (None, Some(_)) => true,
        _ => false,
    };

    if needs_update {
        if let Some(config_content) = &configuration_file_state.config_file_content {
            // Stop visualization if running before updating config
            let was_running = state.visualization_running;
            if was_running {
                state.stop_visualization();
            }

            // Try to parse the config, handle errors gracefully
            // Use catch_unwind because import_config uses .expect() internally
            let config_result =
                std::panic::catch_unwind(|| fosr_lib::config::import_config(config_content));

            match config_result {
                Ok(config) => {
                    state.update_from_config(&config);
                    state.config_content = Some(config_content.clone());
                    // Only auto-restart if visualization was running before config change
                    if was_running {
                        state.auto_start_countdown = Some(10);
                    }
                    state.reset_view_requested = true;
                }
                Err(e) => {
                    // Log the error once and reset to default state instead of crashing
                    // Store the config content so we don't retry parsing every frame
                    log::error!("Failed to parse configuration: {:?}", e);
                    *state = VisualizationTabState::default();
                    state.config_content = Some(config_content.clone());
                    state.reset_view_requested = true;
                }
            }
        }
    }
}

/// Process incoming flow events from the streamer
fn process_flow_events(state: &mut VisualizationTabState) {
    let events: Vec<FlowEvent> = if let Some(ref receiver) = state.flow_receiver {
        receiver.try_iter().collect()
    } else {
        return;
    };

    let now = web_time::Instant::now();

    for event in events {
        // Determine if this flow should be displayed:
        // - Both IPs known: display
        // - One IP known, one unknown: display as host<->Internet
        // - Both IPs unknown: skip (Internet<->Internet)
        let src_known = state.is_known_ip(event.src_ip);
        let dst_known = state.is_known_ip(event.dst_ip);

        log::debug!(
            "Flow: {} -> {} | src_known={}, dst_known={}",
            event.src_ip,
            event.dst_ip,
            src_known,
            dst_known
        );

        if !src_known && !dst_known {
            // Both are Internet IPs - skip this flow
            log::debug!("  -> Skipping (Internet<->Internet)");
            continue;
        }

        // Increment total flows counter
        state.total_flows += 1;

        // Map IPs to display IPs (unknown -> INTERNET_IP)
        let display_src = if src_known { event.src_ip } else { INTERNET_IP };
        let display_dst = if dst_known { event.dst_ip } else { INTERNET_IP };

        log::debug!(
            "  -> Displayed as: {} -> {} ({:?})",
            display_src,
            display_dst,
            event.protocol
        );

        let key = (display_src, display_dst);
        let reverse_key = (display_dst, display_src);

        let direction = if state.active_links.contains_key(&reverse_key) {
            LinkDirection::Bidirectional
        } else {
            LinkDirection::Forward
        };

        state.active_links.insert(
            key,
            ActiveLink {
                protocol: event.protocol,
                start_time: now,
                direction,
            },
        );

        // Increment flow counters on nodes and edges
        if let (Some(&src_idx), Some(&dst_idx)) = (
            state.ip_to_node.get(&display_src),
            state.ip_to_node.get(&display_dst),
        ) {
            // Find the edge (undirected graph, so check both directions)
            let edge_idx = state
                .graph
                .g()
                .find_edge(src_idx, dst_idx)
                .or_else(|| state.graph.g().find_edge(dst_idx, src_idx));

            if let Some(edge_idx) = edge_idx {
                // Increment node flow counters
                if let Some(node) = state.graph.g_mut().node_weight_mut(src_idx) {
                    node.payload_mut().flow_count += 1;
                }
                if let Some(node) = state.graph.g_mut().node_weight_mut(dst_idx) {
                    node.payload_mut().flow_count += 1;
                }
                // Increment edge flow counter (for thickness)
                if let Some(edge) = state.graph.g_mut().edge_weight_mut(edge_idx) {
                    edge.payload_mut().flow_count += 1;
                }
            }
        }
    }

    // Update max_flow_count for all nodes (for proportional sizing)
    let max_node_flow = state
        .graph
        .g()
        .node_indices()
        .filter_map(|idx| state.graph.g().node_weight(idx))
        .map(|n| n.payload().flow_count)
        .max()
        .unwrap_or(0);

    for idx in state.graph.g().node_indices().collect::<Vec<_>>() {
        if let Some(node) = state.graph.g_mut().node_weight_mut(idx) {
            node.payload_mut().max_flow_count = max_node_flow;
        }
    }

    // Update max_flow_count for all edges (for proportional sizing)
    let max_edge_flow = state
        .graph
        .g()
        .edge_indices()
        .filter_map(|idx| state.graph.g().edge_weight(idx))
        .map(|e| e.payload().flow_count)
        .max()
        .unwrap_or(0);

    for idx in state.graph.g().edge_indices().collect::<Vec<_>>() {
        if let Some(edge) = state.graph.g_mut().edge_weight_mut(idx) {
            edge.payload_mut().max_flow_count = max_edge_flow;
        }
    }
}

/// Update active links (remove expired ones)
fn update_active_links(state: &mut VisualizationTabState) {
    let now = web_time::Instant::now();
    // Base display time is 0.5s, adjusted by speed (faster = shorter display)
    let base_timeout_ms = 500.0;
    let speed = *state.speed.read().unwrap();
    let timeout = std::time::Duration::from_millis((base_timeout_ms / speed) as u64);

    state
        .active_links
        .retain(|_, link| now.duration_since(link.start_time) < timeout);
}

/// Update graph edges based on active links
fn update_graph_edges(state: &mut VisualizationTabState) {
    let graph = &mut state.graph;

    // Collect edge info first to avoid borrow issues
    // Each node can have multiple IPs, so we collect all IP lists for matching
    let edges_data: Vec<(
        petgraph::graph::EdgeIndex,
        Vec<std::net::Ipv4Addr>,
        Vec<std::net::Ipv4Addr>,
    )> = graph
        .g()
        .edge_indices()
        .map(|edge| {
            let (source, target) = graph.g().edge_endpoints(edge).unwrap();
            let src_ips = graph.g()[source].payload().ip_addrs.clone();
            let dst_ips = graph.g()[target].payload().ip_addrs.clone();
            (edge, src_ips, dst_ips)
        })
        .collect();

    for (edge, src_ips, dst_ips) in edges_data {
        // Check all IP combinations for an active link
        let mut new_state = EdgeState::Inactive;

        'outer: for src_ip in &src_ips {
            for dst_ip in &dst_ips {
                let forward_key = (*src_ip, *dst_ip);
                let reverse_key = (*dst_ip, *src_ip);

                if let Some(link) = state.active_links.get(&forward_key) {
                    new_state = EdgeState::Active {
                        protocol: link.protocol,
                        start_time: link.start_time,
                        direction: link.direction.clone(),
                    };
                    break 'outer;
                } else if let Some(link) = state.active_links.get(&reverse_key) {
                    new_state = EdgeState::Active {
                        protocol: link.protocol,
                        start_time: link.start_time,
                        // we are using the reverse key, so we need to reverse the direction
                        direction: match link.direction {
                            LinkDirection::Forward => LinkDirection::Backward,
                            LinkDirection::Backward => LinkDirection::Forward,
                            LinkDirection::Bidirectional => LinkDirection::Bidirectional,
                        },
                    };
                    break 'outer;
                }
            }
        }

        // Update edge state (flow_count is preserved)
        if let Some(edge_mut) = graph.g_mut().edge_weight_mut(edge) {
            edge_mut.payload_mut().state = new_state;
        }
    }
}

/// Show the generation options
fn show_generation_options(ui: &mut egui::Ui, state: &mut RunState) {
    ui.columns(2, |cols| {
        // --- Column 1: Duration & Time ---
        let col1 = &mut cols[0];
        col1.set_min_width(280.0);

        // Duration
        col1.horizontal(|ui| {
            ui.label("Duration");
            info_icon(ui, "Minimum pcap traffic duration described in human-friendly time, such as \"30m\", \"1h\", \"2d\" or \"2days 30min 5s\".");

            // Preset buttons
            for preset in ["5min", "1h", "24h"] {
                if ui.small_button(preset).clicked() {
                    state.generation.duration_str = preset.to_string();
                    state.generation.duration_validation.set_ok();
                }
            }

            let text_response = egui::TextEdit::singleline(&mut state.generation.duration_str)
                .desired_width(80.0)
                .hint_text("ex: 30m, 1h, 2d")
                .ui(ui);

            if text_response.changed() {
                match validate_duration(&state.generation.duration_str) {
                    Ok(_) => {
                        state.generation.duration_validation.set_ok();
                    }
                    Err(msg) => {
                        state.generation.duration_validation.set_err(msg);
                    }
                }
            }

            show_field_error(ui, &state.generation.duration_validation);
        });

        col1.add_space(8.0);

        // Use current time
        col1.horizontal(|ui| {
            ui.checkbox(&mut state.generation.use_current_time, "Use current time for start time");
            info_icon(ui, "Beginning time of the pcap. By default, use the current time. For deterministic generation, you must specify this along with duration, timezone and seed.");
        });

        if !state.generation.use_current_time {
            col1.horizontal(|ui| {
                ui.label("Start time");
                let current_year = Local::now().date_naive().year();
                ui.add(
                    DatePickerButton::new(&mut state.generation.start_date)
                        .start_end_years((current_year - 5)..=(current_year + 30)),
                );
                ui.add(
                    TimePickerButton::new(&mut state.generation.start_hour)
                        .show_seconds(true)
                        .use_dragvalue(true),
                );
            });

            col1.add_space(8.0);

            col1.horizontal(|ui| {
                if ui
                    .checkbox(&mut state.generation.use_local_timezone, "Use local timezone")
                    .clicked()
                {
                    if state.generation.use_local_timezone {
                        state.generation.timezone_input = String::new();
                        state.generation.timezone_validation.set_ok();
                    } else {
                        state.generation.timezone_input = Tz::CET.to_string();
                    }
                }
                info_icon(ui, "Timezone used for realistic work hours. Use an IANA time zone (like Europe/Paris) or an abbreviation (like CET). The offset is assumed constant during the generation time range.");

                if !state.generation.use_local_timezone {
                    timezone_picker(ui, &mut state.generation);

                    let result = validate_timezone(&state.generation.timezone_input);
                    if result.is_ok() {
                        state.generation.timezone_validation.set_ok();
                    } else {
                        state.generation.timezone_validation.set_err(result.err().unwrap());
                    }
                }
            });
        } else {
            state.generation.timezone_validation.set_ok();
        }

        // Show the equivalent UTC start time (or error if timezone is invalid)
        let utc_text: Option<String> = if state.generation.use_current_time {
            Some(chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string())
        } else {
            let local_dt = state
                .generation
                .start_date
                .and_time(state.generation.start_hour);

            let utc = if state.generation.use_local_timezone {
                Local::now()
                    .timezone()
                    .from_local_datetime(&local_dt)
                    .earliest()
                    .map(|dt| dt.with_timezone(&chrono::Utc))
            } else {
                state
                    .generation
                    .timezone_input
                    .parse::<Tz>()
                    .ok()
                    .and_then(|tz| local_dt.and_local_timezone(tz).earliest())
                    .map(|dt| dt.with_timezone(&chrono::Utc))
            };

            utc.map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                .or_else(|| {
                    if !state.generation.use_local_timezone {
                        Some("select a valid timezone".to_string())
                    } else {
                        None
                    }
                })
        };

        if let Some(text) = utc_text {
            col1.label(
                egui::RichText::new(format!("Start time (UTC): {}", text))
                    .color(egui::Color32::GRAY),
            );
        }

        // --- Column 2: Seed & Advanced ---
        let col2 = &mut cols[1];
        col2.set_min_width(200.0);

        // Seed
        col2.horizontal(|ui| {
            ui.checkbox(&mut state.generation.use_seed, "Seed");
            info_icon(ui, "Seed for random number generation. For deterministic generation, you must also specify duration, start time, and timezone.");

            if state.generation.use_seed {
                let response = ui.add(
                    egui::TextEdit::singleline(&mut state.generation.seed_input)
                        .hint_text("enter a seed value")
                        .desired_width(120.0),
                );

                if response.changed() {
                    match validate_optional_u64(&state.generation.seed_input) {
                        Ok(_) => {
                            state.generation.seed_validation.set_ok();
                        }
                        Err(msg) => {
                            state.generation.seed_validation.set_err(msg);
                        }
                    }
                }

                show_field_error(ui, &state.generation.seed_validation);
            } else {
                state.generation.seed_validation.set_ok();
            }
        });

        col2.add_space(8.0);

        // Advanced options
        col2.horizontal(|ui| {
            ui.checkbox(&mut state.generation.taint, "Taint the packets");
            info_icon(ui, "Taint the packets with special markers for identification.");
        });
        col2.horizontal(|ui| {
            ui.checkbox(&mut state.generation.order_pcap, "Order temporally");
            info_icon(ui, "Enable temporal sorting of the generated pcap. Disable to reduce significantly the RAM usage.");
        });

        col2.add_space(8.0);

        // Validation errors
        if let Some((name, spec, err)) = first_invalid_param(&state.generation) {
            col2.colored_label(
                egui::Color32::RED,
                format!("Invalid parameter: {name}. Expected: {spec}. ({err})"),
            );
        }
    });
}

/// Start the generation process
fn start_generation(
    state: &mut RunState,
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

/// Poll generation receivers for updates
fn poll_generation_receivers(ctx: &egui::Context, state: &mut RunState) {
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

/// Show the bottom panel with action bar and expandable options
fn show_bottom_panel(
    ctx: &egui::Context,
    state: &mut RunState,
    configuration_file_state: &ConfigurationFileState,
) {
    // Options panel (shown above action bar when expanded)
    if state.panel_open {
        egui::TopBottomPanel::bottom("run_options_panel")
            .frame(
                egui::Frame::side_top_panel(&ctx.style())
                    .inner_margin(egui::Margin::symmetric(8, 8))
                    .fill(ctx.style().visuals.panel_fill),
            )
            .resizable(false)
            .show(ctx, |ui| {
                show_generation_options(ui, state);
            });
    }

    // Action bar (always visible)
    egui::TopBottomPanel::bottom("run_bottom_bar")
        .frame(
            egui::Frame::side_top_panel(&ctx.style()).inner_margin(egui::Margin::symmetric(8, 4)),
        )
        .show(ctx, |ui| {
            let is_generating = state.generation.is_generating();
            let is_complete = state.generation.is_complete();
            let can_generate = first_invalid_param(&state.generation).is_none();

            ui.horizontal(|ui| {
                // Generate button (always visible, same style/position)
                if !is_generating {
                    ui.add_enabled_ui(can_generate, |ui| {
                        let accent = ui.visuals().selection.bg_fill;
                        let generate_button = egui::Button::new(
                            egui::RichText::new(format!(
                                "{} Generate",
                                egui_material_icons::icons::ICON_PLAY_ARROW
                            ))
                            .size(13.0),
                        )
                        .fill(accent)
                        .min_size(egui::vec2(85.0, 24.0));
                        if ui
                            .add(generate_button)
                            .on_hover_text("Generate PCAP from configuration")
                            .clicked()
                        {
                            start_generation(state, configuration_file_state, ctx);
                        }
                    });
                }

                // Stop button (when generating)
                if is_generating {
                    let stop_button = egui::Button::new(
                        egui::RichText::new(format!(
                            "{} Stop",
                            egui_material_icons::icons::ICON_STOP
                        ))
                        .size(13.0),
                    )
                    .fill(egui::Color32::from_rgb(200, 80, 80))
                    .min_size(egui::vec2(75.0, 24.0));
                    if ui
                        .add(stop_button)
                        .on_hover_text("Cancel generation")
                        .clicked()
                    {
                        state.generation.cancelled.store(true, Ordering::Relaxed);
                        state.generation.progress = 0.0;
                        state.generation.progress_receiver = None;
                        state.generation.pcap_receiver = None;
                        state.generation.throughput_receiver = None;
                    }
                }

                // Save/Open buttons (when complete)
                if is_complete {
                    #[cfg(not(target_arch = "wasm32"))]
                    let save_text = format!("{} Save", egui_material_icons::icons::ICON_SAVE);
                    #[cfg(target_arch = "wasm32")]
                    let save_text =
                        format!("{} Download", egui_material_icons::icons::ICON_DOWNLOAD);

                    let save_button = egui::Button::new(egui::RichText::new(save_text).size(13.0))
                        .min_size(egui::vec2(75.0, 24.0));
                    if ui.add(save_button).clicked() {
                        let pcap_bytes = state.generation.pcap_bytes.clone();
                        #[cfg(not(target_arch = "wasm32"))]
                        {
                            let data = pcap_bytes.as_ref().unwrap().as_slice();
                            match save_file_desktop(data, &state.generation.output_file_name) {
                                Ok(file_handle) => {
                                    log::info!(
                                        "Successfully wrote to file: {}",
                                        file_handle.path().to_string_lossy()
                                    );
                                }
                                Err(e) => {
                                    log::error!("Failed to save file: {:?}", e);
                                    state.generation.error =
                                        Some(format!("Failed to save file: {e}"));
                                }
                            }
                        }

                        #[cfg(target_arch = "wasm32")]
                        {
                            let file_name = state.generation.output_file_name.clone();
                            wasm_bindgen_futures::spawn_local(async move {
                                let data = pcap_bytes.as_ref().unwrap().as_slice();
                                match save_file_wasm(data, &file_name).await {
                                    Ok(_) => log::info!("File written successfully!"),
                                    Err(e) => log::error!("Failed to write file on WASM: {:?}", e),
                                }
                            });
                        }
                    }

                    // Open in Wireshark button (native only)
                    #[cfg(not(target_arch = "wasm32"))]
                    {
                        let open_button = egui::Button::new(
                            egui::RichText::new(format!(
                                "{} Open",
                                egui_material_icons::icons::ICON_LAN
                            ))
                            .size(13.0),
                        )
                        .min_size(egui::vec2(75.0, 24.0));
                        let response =
                            ui.add_enabled(state.generation.wireshark_available, open_button);
                        let response = if state.generation.wireshark_available {
                            response.on_hover_text("Open in Wireshark")
                        } else {
                            response.on_disabled_hover_text("Wireshark not found in PATH")
                        };
                        if response.clicked() {
                            if let Some(ref pcap_bytes) = state.generation.pcap_bytes {
                                match open_in_wireshark(
                                    pcap_bytes,
                                    &mut state.generation.temp_pcap_files,
                                ) {
                                    Ok(_) => log::info!("Opened PCAP in Wireshark"),
                                    Err(e) => {
                                        log::error!("Failed to open in Wireshark: {:?}", e);
                                        state.generation.error =
                                            Some(format!("Failed to open in Wireshark: {e}"));
                                    }
                                }
                            }
                        }
                    }
                }

                // Error display (when there's an error)
                if let Some(error) = &state.generation.error {
                    ui.colored_label(egui::Color32::RED, error);
                }

                // Options toggle button (right-aligned) with progress bar and throughput
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    // Options button (rightmost)
                    let icon = if state.panel_open {
                        egui_material_icons::icons::ICON_KEYBOARD_ARROW_DOWN
                    } else {
                        egui_material_icons::icons::ICON_KEYBOARD_ARROW_UP
                    };
                    let tooltip = if state.panel_open {
                        "Hide options"
                    } else {
                        "Show options"
                    };
                    if ui
                        .button(format!("{} Options", icon))
                        .on_hover_text(tooltip)
                        .clicked()
                    {
                        state.panel_open = !state.panel_open;
                        state.visualization.delayed_fit_countdown = Some(2); // Delay by 2 frames
                    }

                    // Throughput (when complete) - left of Options
                    if is_complete {
                        if let Some(throughput) = &state.generation.throughput {
                            ui.label(format!("Throughput: {throughput}"));
                        }
                    }

                    // Progress bar (when generating) - left of Throughput/Options
                    if is_generating {
                        let progress = egui::ProgressBar::new(state.generation.progress)
                            .text("")
                            .fill(egui::Color32::from_rgb(144, 238, 144));
                        ui.add(progress);
                    }
                });
            });
        });
}

/// Render the graph view with overlays
fn render_graph_view(ui: &mut egui::Ui, state: &mut RunState) {
    let inner_response = egui::CentralPanel::default().show(ui.ctx(), |ui| {
        // Enable node clicking and dragging
        let interactions = egui_graphs::SettingsInteraction::new()
            .with_node_clicking_enabled(true)
            .with_dragging_enabled(true);

        // Reset view on window resize
        let screen_size = ui.ctx().content_rect().size();
        match state.visualization.last_screen_size {
            Some(last) if last != screen_size => {
                state.visualization.last_screen_size = Some(screen_size);
                state.visualization.reset_view_requested = true;
            }
            None => state.visualization.last_screen_size = Some(screen_size),
            _ => {}
        }

        // When reset is requested, enable fit-to-screen for one frame
        // so egui_graphs recalculates the proper zoom/pan to center the graph
        let fit_to_screen = state.visualization.reset_view_requested;
        if state.visualization.reset_view_requested {
            state.visualization.reset_view_requested = false;
        }

        let mut graph_view = egui_graphs::GraphView::<
            NodeData,
            EdgeData,
            petgraph::Undirected,
            petgraph::stable_graph::DefaultIx,
            NetworkNodeShape,
            NetworkEdgeShape,
            egui_graphs::FruchtermanReingoldWithCenterGravityState,
            egui_graphs::LayoutForceDirected<egui_graphs::FruchtermanReingoldWithCenterGravity>,
        >::new(&mut state.visualization.graph)
        .with_interactions(&interactions)
        .with_event_sink(&state.visualization.events_buffer)
        .with_styles(&egui_graphs::SettingsStyle::new().with_labels_always(true))
        .with_navigations(
            &egui_graphs::SettingsNavigation::new()
                .with_fit_to_screen_enabled(fit_to_screen)
                .with_fit_to_screen_padding(0.15) // padding to avoid cropping with labels and overlays
                .with_zoom_and_pan_enabled(true),
        );

        // Disable force-directed layout to preserve circle layout
        // TODO: handle this properly instead of just deactivating the auto-layout
        if !state.visualization.layout_initialized {
            let layout_state = egui_graphs::FruchtermanReingoldWithCenterGravityState {
                base: egui_graphs::FruchtermanReingoldState {
                    is_running: false,
                    ..Default::default()
                },
                extras: Default::default(),
            };
            egui_graphs::set_layout_state(ui, layout_state, None);
            state.visualization.layout_initialized = true;
        }

        ui.add(&mut graph_view);

        // Handle screenshot export state machine
        handle_screenshot_export(ui, &mut state.visualization);

        // Hide overlays during export to get clean screenshot
        if state.visualization.export_state != ExportState::Idle {
            return;
        }

        // Render overlays
        render_overlay_buttons(ui, &mut state.visualization);
        render_overlay_stats(ui, &state.visualization);
        render_overlay_node_legend(ui);
        render_overlay_edge_legend(ui);
    });

    // Use panel rect directly - it's already in screen coordinates
    // and represents the full panel area (ui.max_rect() excludes internal padding)
    let panel_rect = inner_response.response.rect;
    state.visualization.graph_rect = Some(panel_rect);
}
