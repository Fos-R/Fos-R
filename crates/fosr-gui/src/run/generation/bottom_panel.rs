//! Bottom panel UI for the Run tab.
//!
//! Contains the action bar with Generate/Stop/Save buttons and
//! the expandable generation options panel.

use super::options::render_generation_options;
use super::process::start_generation;
use super::validation::first_invalid_param;
#[cfg(not(target_arch = "wasm32"))]
use super::wireshark::open_in_wireshark;
use egui_material_icons::icons::{ICON_KEYBOARD_ARROW_DOWN, ICON_KEYBOARD_ARROW_UP, ICON_PLAY_ARROW, ICON_STOP};
#[cfg(not(target_arch = "wasm32"))]
use egui_material_icons::icons::{ICON_LAN, ICON_SAVE};
#[cfg(target_arch = "wasm32")]
use egui_material_icons::icons::{ICON_DOWNLOAD};
use crate::run::state::RunTabState;
use crate::shared::config::state::ConfigFileState;
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
pub fn render_bottom_panel(
    ctx: &egui::Context,
    state: &mut RunTabState,
    configuration_file_state: &ConfigFileState,
) {
    if state.panel_open {
        render_options_panel(ctx, state);
    }
    render_action_bar(ctx, state, configuration_file_state);
}

/// Options panel shown above the action bar when expanded.
fn render_options_panel(ctx: &egui::Context, state: &mut RunTabState) {
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
            render_generation_options(ui, state);
        });
}

/// Action bar with Generate/Stop/Save buttons and progress indicators.
fn render_action_bar(
    ctx: &egui::Context,
    state: &mut RunTabState,
    configuration_file_state: &ConfigFileState,
) {
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
                // Left side: action buttons
                if !is_generating {
                    render_generate_button(ui, state, configuration_file_state, ctx, can_generate);
                }
                if is_generating {
                    render_stop_button(ui, state);
                }
                if is_complete {
                    render_completion_buttons(ui, state);
                }
                if let Some(error) = &state.generation.error {
                    ui.colored_label(COLOR_ERROR, error);
                }

                // Right side: options toggle, throughput, progress
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    render_options_toggle(ui, state);
                    if is_complete {
                        render_throughput(ui, state);
                    }
                    if is_generating {
                        render_progress_bar(ui, state);
                    }
                });
            });
        });
}

/// Generate button with accent color.
fn render_generate_button(
    ui: &mut egui::Ui,
    state: &mut RunTabState,
    configuration_file_state: &ConfigFileState,
    ctx: &egui::Context,
    can_generate: bool,
) {
    ui.add_enabled_ui(can_generate, |ui| {
        let accent = ui.visuals().selection.bg_fill;
        let button = egui::Button::new(
            egui::RichText::new(format!(
                "{} Generate",
                ICON_PLAY_ARROW
            ))
                .size(TEXT_SIZE_MD),
        )
            .fill(accent)
            .min_size(egui::vec2(BUTTON_MIN_WIDTH_LG, BUTTON_HEIGHT));

        if ui.add(button).on_hover_text("Generate PCAP from configuration").clicked() {
            start_generation(state, configuration_file_state, ctx);
        }
    });
}

/// Stop button to cancel ongoing generation.
fn render_stop_button(ui: &mut egui::Ui, state: &mut RunTabState) {
    let button = egui::Button::new(
        egui::RichText::new(format!("{} Stop", ICON_STOP))
            .size(TEXT_SIZE_MD),
    )
        .fill(COLOR_STOP)
        .min_size(egui::vec2(BUTTON_MIN_WIDTH_SM, BUTTON_HEIGHT));

    if ui.add(button).on_hover_text("Cancel generation").clicked() {
        state.generation.cancelled.store(true, Ordering::Relaxed);
        state.generation.progress = 0.0;
        state.generation.progress_receiver = None;
        state.generation.pcap_receiver = None;
        state.generation.throughput_receiver = None;
    }
}

/// Save and Wireshark buttons shown when generation is complete.
fn render_completion_buttons(ui: &mut egui::Ui, state: &mut RunTabState) {
    render_save_button(ui, state);
    #[cfg(not(target_arch = "wasm32"))]
    render_wireshark_button(ui, state);
}

/// Save/Download button for the generated PCAP.
fn render_save_button(ui: &mut egui::Ui, state: &mut RunTabState) {
    #[cfg(not(target_arch = "wasm32"))]
    let save_text = format!("{} Save", ICON_SAVE);
    #[cfg(target_arch = "wasm32")]
    let save_text = format!("{} Download", ICON_DOWNLOAD);

    let button = egui::Button::new(egui::RichText::new(save_text).size(TEXT_SIZE_MD))
        .min_size(egui::vec2(BUTTON_MIN_WIDTH_SM, BUTTON_HEIGHT));

    if ui.add(button).clicked() {
        let pcap_bytes = state.generation.pcap_bytes.clone();
        #[cfg(not(target_arch = "wasm32"))]
        save_pcap_desktop(pcap_bytes, state);

        #[cfg(target_arch = "wasm32")]
        save_pcap_wasm(pcap_bytes, &state.generation.output_file_name);
    }
}

/// Saves PCAP to disk on desktop platforms.
#[cfg(not(target_arch = "wasm32"))]
fn save_pcap_desktop(pcap_bytes: Option<Vec<u8>>, state: &mut RunTabState) {
    let Some(data) = pcap_bytes else {
        log::error!("No PCAP data available to save");
        state.generation.error = Some("No PCAP data available".to_string());
        return;
    };
    match save_file_desktop(&data, &state.generation.output_file_name) {
        Ok(file_handle) => {
            log::info!("Successfully wrote to file: {}", file_handle.path().to_string_lossy());
        }
        Err(e) => {
            log::error!("Failed to save file: {:?}", e);
            state.generation.error = Some(format!("Failed to save file: {e}"));
        }
    }
}

/// Triggers PCAP download on WASM platforms.
#[cfg(target_arch = "wasm32")]
fn save_pcap_wasm(pcap_bytes: Option<Vec<u8>>, file_name: &str) {
    let Some(data) = pcap_bytes else {
        log::error!("No PCAP data available to download");
        return;
    };
    let file_name = file_name.to_string();
    wasm_bindgen_futures::spawn_local(async move {
        match save_file_wasm(&data, &file_name).await {
            Ok(_) => log::info!("File written successfully!"),
            Err(e) => log::error!("Failed to write file on WASM: {:?}", e),
        }
    });
}

/// Wireshark button (native only) to open PCAP in external tool.
#[cfg(not(target_arch = "wasm32"))]
fn render_wireshark_button(ui: &mut egui::Ui, state: &mut RunTabState) {
    let button = egui::Button::new(
        egui::RichText::new(format!("{} Open", ICON_LAN))
            .size(TEXT_SIZE_MD),
    )
        .min_size(egui::vec2(BUTTON_MIN_WIDTH_SM, BUTTON_HEIGHT));

    let response = ui.add_enabled(state.generation.wireshark_available, button);
    let response = if state.generation.wireshark_available {
        response.on_hover_text("Open in Wireshark")
    } else {
        response.on_disabled_hover_text("Wireshark not found in PATH")
    };

    if response.clicked() {
        if let Some(ref pcap_bytes) = state.generation.pcap_bytes {
            match open_in_wireshark(pcap_bytes, &mut state.generation.temp_pcap_files) {
                Ok(_) => log::info!("Opened PCAP in Wireshark"),
                Err(e) => {
                    log::error!("Failed to open in Wireshark: {:?}", e);
                    state.generation.error = Some(format!("Failed to open in Wireshark: {e}"));
                }
            }
        }
    }
}

/// Options toggle button to show/hide the options panel.
fn render_options_toggle(ui: &mut egui::Ui, state: &mut RunTabState) {
    let icon = if state.panel_open {
        ICON_KEYBOARD_ARROW_DOWN
    } else {
        ICON_KEYBOARD_ARROW_UP
    };
    let tooltip = if state.panel_open { "Hide options" } else { "Show options" };

    if ui.button(format!("{} Options", icon)).on_hover_text(tooltip).clicked() {
        state.panel_open = !state.panel_open;
        state.visualization.view.delayed_fit_countdown = Some(DELAY_FRAMES_QUICK);
    }
}

/// Throughput display shown when generation is complete.
fn render_throughput(ui: &mut egui::Ui, state: &RunTabState) {
    if let Some(throughput) = &state.generation.throughput {
        ui.label(format!("Throughput: {throughput}"));
    }
}

/// Progress bar shown during generation.
fn render_progress_bar(ui: &mut egui::Ui, state: &RunTabState) {
    let progress = egui::ProgressBar::new(state.generation.progress)
        .text("")
        .fill(COLOR_SUCCESS);
    ui.add(progress);
}
