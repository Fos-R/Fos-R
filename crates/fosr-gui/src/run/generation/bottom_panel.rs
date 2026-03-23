//! Bottom panel UI for the Run tab.
//!
//! Contains the action bar with Generate/Stop/Save buttons and
//! the expandable generation options panel.

use super::options::show_generation_options;
use super::process::start_generation;
use super::validation::first_invalid_param;
#[cfg(not(target_arch = "wasm32"))]
use super::wireshark::open_in_wireshark;
use crate::run::state::RunTabState;
use crate::shared::config::state::ConfigurationFileState;
use crate::shared::constants::colors::{COLOR_ERROR, COLOR_STOP, COLOR_SUCCESS};
use crate::shared::constants::ui::{
    BOTTOM_BAR_INNER_MARGIN, BUTTON_HEIGHT, BUTTON_MIN_WIDTH_LG, BUTTON_MIN_WIDTH_SM,
    DELAY_FRAMES_QUICK, OPTIONS_PANEL_INNER_MARGIN, TEXT_SIZE_MD,
};
#[cfg(not(target_arch = "wasm32"))]
use crate::shared::file_io::save_file_desktop;
#[cfg(target_arch = "wasm32")]
use crate::shared::file_io::save_file_wasm;
use eframe::egui;
use std::sync::atomic::Ordering;

/// Show the bottom panel with action bar and expandable options.
///
/// The panel consists of:
/// - Options panel (shown when expanded): generation parameters
/// - Action bar (always visible): Generate/Stop/Save buttons, progress bar
pub fn show_bottom_panel(
    ctx: &egui::Context,
    state: &mut RunTabState,
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
                        state.visualization.view.delayed_fit_countdown = Some(DELAY_FRAMES_QUICK);
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
