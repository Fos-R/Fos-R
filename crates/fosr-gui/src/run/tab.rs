//! Run tab: live network visualization combined with PCAP generation controls.

use super::config_handling::handle_config_changes;
use super::flow_processing::{process_flow_events, update_active_links, update_graph_edges};
use super::generation_options::show_generation_options;
use super::generation_process::{poll_generation_receivers, start_generation};
use super::state::RunState;
use crate::generation::validation::first_invalid_param;
#[cfg(not(target_arch = "wasm32"))]
use crate::generation::wireshark::open_in_wireshark;
use crate::shared::colors::{COLOR_ERROR, COLOR_STOP, COLOR_SUCCESS};
use crate::shared::configuration_file::{ConfigurationFileState, load_config_file_contents};
#[cfg(not(target_arch = "wasm32"))]
use crate::shared::file_io::save_file_desktop;
#[cfg(target_arch = "wasm32")]
use crate::shared::file_io::save_file_wasm;
use crate::shared::ui_constants::{
    BOTTOM_BAR_INNER_MARGIN, BUTTON_HEIGHT, BUTTON_MIN_WIDTH_LG, BUTTON_MIN_WIDTH_SM,
    DELAY_FRAMES_QUICK, FIT_TO_SCREEN_PADDING, OPTIONS_PANEL_INNER_MARGIN, TEXT_SIZE_MD,
};
use crate::visualization::node_modal::{process_graph_events, render_node_info_modal};
use crate::visualization::overlays::{
    render_overlay_buttons, render_overlay_edge_legend, render_overlay_node_legend,
    render_overlay_stats,
};
use crate::visualization::screenshot::handle_screenshot_export;
use crate::visualization::shapes::{NetworkEdgeShape, NetworkNodeShape};
use crate::visualization::state::{EdgeData, ExportState, NodeData};
use eframe::egui;
use std::sync::atomic::Ordering;

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
                    .inner_margin(egui::Margin::symmetric(
                        OPTIONS_PANEL_INNER_MARGIN.0,
                        OPTIONS_PANEL_INNER_MARGIN.1,
                    ))
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
            egui::Frame::side_top_panel(&ctx.style()).inner_margin(egui::Margin::symmetric(
                BOTTOM_BAR_INNER_MARGIN.0,
                BOTTOM_BAR_INNER_MARGIN.1,
            )),
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
                            .size(TEXT_SIZE_MD),
                        )
                        .fill(accent)
                        .min_size(egui::vec2(BUTTON_MIN_WIDTH_LG, BUTTON_HEIGHT));
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
                        .size(TEXT_SIZE_MD),
                    )
                    .fill(COLOR_STOP)
                    .min_size(egui::vec2(BUTTON_MIN_WIDTH_SM, BUTTON_HEIGHT));
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

                    let save_button =
                        egui::Button::new(egui::RichText::new(save_text).size(TEXT_SIZE_MD))
                            .min_size(egui::vec2(BUTTON_MIN_WIDTH_SM, BUTTON_HEIGHT));
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
                            .size(TEXT_SIZE_MD),
                        )
                        .min_size(egui::vec2(BUTTON_MIN_WIDTH_SM, BUTTON_HEIGHT));
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
                    ui.colored_label(COLOR_ERROR, error);
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
                        state.visualization.delayed_fit_countdown = Some(DELAY_FRAMES_QUICK);
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
                            .fill(COLOR_SUCCESS);
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
                .with_fit_to_screen_padding(FIT_TO_SCREEN_PADDING) // padding to avoid cropping with labels and overlays
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
