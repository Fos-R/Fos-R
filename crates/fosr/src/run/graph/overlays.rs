//! Graph overlay UI: control buttons, stats display, and legends for nodes/edges.

use super::state::{ScreenshotStateMachine, SubnetDisplayMode, VisualizationState};
use crate::shared::assets::{IMG_COMPUTER, IMG_INTERNET, IMG_SERVER};
use crate::shared::constants::colors::{
    COLOR_EDGE_INACTIVE, COLOR_ICON_TINT_DARK, COLOR_ICON_TINT_LIGHT, COLOR_STOP,
    color_for_protocol,
};
use crate::shared::constants::ui::{
    LEGEND_ICON_SIZE, LEGEND_MARKER_RADIUS, OVERLAY_MARGIN, PLAYBACK_SPEED_EPSILON,
    PLAYBACK_SPEED_STEPS, SPACING_NEGATIVE_XS,
};
use eframe::egui;
use egui_material_icons::icons::{
    ICON_ADD, ICON_AUTORENEW, ICON_FIT_SCREEN, ICON_IMAGE, ICON_LAN, ICON_PLAY_ARROW, ICON_REMOVE,
    ICON_RESTART_ALT, ICON_STOP,
};
use fosr_lib::structs::L7Proto;
use strum::IntoEnumIterator;

/// Render a legend item with a colored circle (for edge protocols).
fn legend_item_inline(ui: &mut egui::Ui, label: &str, color: egui::Color32) {
    ui.horizontal(|ui| {
        let rect = ui
            .allocate_space(egui::vec2(LEGEND_ICON_SIZE, LEGEND_ICON_SIZE))
            .1;
        let painter = ui.painter();
        painter.circle_filled(rect.center(), LEGEND_MARKER_RADIUS, color);
        ui.add_space(SPACING_NEGATIVE_XS);
        ui.label(label);
    });
}

/// Render a legend item with an icon image (for node types).
fn legend_item_with_image(ui: &mut egui::Ui, label: &str, image: egui::ImageSource) {
    ui.horizontal(|ui| {
        let tint = if ui.style().visuals.dark_mode {
            COLOR_ICON_TINT_DARK
        } else {
            COLOR_ICON_TINT_LIGHT
        };
        ui.add(
            egui::Image::new(image)
                .fit_to_exact_size(egui::vec2(LEGEND_ICON_SIZE, LEGEND_ICON_SIZE))
                .tint(tint),
        );
        ui.add_space(SPACING_NEGATIVE_XS);
        ui.label(label);
    });
}

/// Render overlay buttons in the top-left corner of the graph.
pub fn render_overlay_buttons(
    ui: &mut egui::Ui,
    state: &mut VisualizationState,
    models: Option<fosr_lib::models::ArcModels>,
) {
    let local_rect = ui.max_rect();

    egui::Area::new(egui::Id::new("viz_overlay_buttons"))
        .fixed_pos(local_rect.left_top() + egui::vec2(OVERLAY_MARGIN, OVERLAY_MARGIN))
        .order(egui::Order::Foreground)
        .show(ui.ctx(), |ui| {
            egui::Frame::popup(ui.style())
                .shadow(egui::epaint::Shadow::NONE)
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        render_playback_controls(ui, state, models);
                        render_view_controls(ui, state);
                        ui.separator();
                        render_speed_controls(ui, state);
                    });
                });
        });
}

/// Render play/stop/restart buttons based on current state.
fn render_playback_controls(
    ui: &mut egui::Ui,
    state: &mut VisualizationState,
    models: Option<fosr_lib::models::ArcModels>,
) {
    match models {
        Some(models) => {
            if !state.flow.running {
                render_play_button(ui, state, models.clone());
                if state.user_has_started {
                    render_restart_button(ui, state, models);
                }
            } else {
                render_stop_button(ui, state);
            }
        }
        None => {
            ui.label("Loading models...");
        }
    }
}

/// Render the Play/Continue button.
///
/// Resumes visualization without resetting flow counts. Uses "Start" label
/// initially, then "Continue" after the user has started at least once.
fn render_play_button(
    ui: &mut egui::Ui,
    state: &mut VisualizationState,
    models: fosr_lib::models::ArcModels,
) {
    let (play_text, play_tooltip) = if state.user_has_started {
        (
            "Continue",
            "Generate new flows, keeping statistics and edge history",
        )
    } else {
        ("Start", "Start the network simulation")
    };
    let accent = ui.visuals().selection.bg_fill;
    let play_button = egui::Button::new(egui::RichText::new(format!(
        "{} {}",
        ICON_PLAY_ARROW, play_text
    )))
    .fill(accent);

    if ui.add(play_button).on_hover_text(play_tooltip).clicked() {
        state.user_has_started = true;
        let speed = state.flow.speed.clone();
        if let Err(e) = state.start_visualization(models, speed, false) {
            log::error!("Failed to start flow streamer: {}", e);
        }
    }
}

/// Render the Restart button.
///
/// Resets all flow counts and starts fresh. Only visible after the user
/// has started at least once (otherwise the Play button shows "Start").
fn render_restart_button(
    ui: &mut egui::Ui,
    state: &mut VisualizationState,
    models: fosr_lib::models::ArcModels,
) {
    if ui
        .button(ICON_RESTART_ALT)
        .on_hover_text("Restart - reset all statistics and edges")
        .clicked()
    {
        let speed = state.flow.speed.clone();
        if let Err(e) = state.start_visualization(models, speed, true) {
            log::error!("Failed to start flow streamer: {}", e);
        }
    }
}

/// Render the Stop button.
fn render_stop_button(ui: &mut egui::Ui, state: &mut VisualizationState) {
    let stop_button =
        egui::Button::new(egui::RichText::new(format!("{} Stop", ICON_STOP))).fill(COLOR_STOP);

    if ui.add(stop_button).clicked() {
        state.stop_visualization();
    }
}

/// Render fit-to-screen, reset layout, subnet mode, and export buttons.
fn render_view_controls(ui: &mut egui::Ui, state: &mut VisualizationState) {
    if ui
        .button(ICON_FIT_SCREEN)
        .on_hover_text("Fit to screen")
        .clicked()
    {
        state.view.fit_to_screen_requested = true;
    }

    if ui
        .button(ICON_AUTORENEW)
        .on_hover_text("Reset node positions")
        .clicked()
    {
        state.view.layout_reset_requested = true;
    }

    render_subnet_mode_menu(ui, state);

    if ui
        .button(ICON_IMAGE)
        .on_hover_text("Export as PNG")
        .clicked()
    {
        state.screenshot_export = ScreenshotStateMachine::HidingOverlays;
    }
}

/// Render the subnet display mode dropdown menu.
fn render_subnet_mode_menu(ui: &mut egui::Ui, state: &mut VisualizationState) {
    let current = state.subnet_mode;
    ui.menu_button(ICON_LAN, |menu_ui| {
        for mode in SubnetDisplayMode::iter() {
            let is_selected = mode == current;
            let btn = egui::Button::new(mode.label()).selected(is_selected);
            if menu_ui.add(btn).on_hover_text(mode.tooltip()).clicked() {
                let was_flat = state.subnet_mode == SubnetDisplayMode::Flat;
                state.subnet_mode = mode;
                state.network.set_subnet_mode(mode);
                // Layout changes between flat and zone modes, so reset
                if was_flat != (mode == SubnetDisplayMode::Flat) {
                    state.view.layout_reset_requested = true;
                }
                menu_ui.close();
            }
        }
    })
    .response
    .on_hover_text("Subnet display mode");
}

/// Render playback speed controls with −/+ buttons.
///
/// Speed is stored in an `Arc<RwLock>` for runtime updates,
/// so we read/write it manually rather than binding directly.
fn render_speed_controls(ui: &mut egui::Ui, state: &mut VisualizationState) {
    // Use into_inner() on poison to recover the value anyway.
    // Lock poisoning only happens if another thread panicked while holding the lock,
    // and for a simple f32 speed value, there's no risk of data corruption.
    let mut speed_value = *state.flow.speed.read().unwrap_or_else(|e| e.into_inner());
    let current_idx = find_speed_step_index(speed_value);

    if ui.button(ICON_REMOVE).on_hover_text("Slow down").clicked()
        && let Some(idx) = current_idx
        && idx > 0
    {
        speed_value = PLAYBACK_SPEED_STEPS[idx - 1];
        *state.flow.speed.write().unwrap_or_else(|e| e.into_inner()) = speed_value;
    }

    ui.label(format!("{:.1}x", speed_value))
        .on_hover_text("Playback speed - controls how fast network flows are simulated");

    if ui.button(ICON_ADD).on_hover_text("Speed up").clicked()
        && let Some(idx) = current_idx
        && idx < PLAYBACK_SPEED_STEPS.len() - 1
    {
        speed_value = PLAYBACK_SPEED_STEPS[idx + 1];
        *state.flow.speed.write().unwrap_or_else(|e| e.into_inner()) = speed_value;
    }
}

/// Find the index of the current speed in the predefined steps.
fn find_speed_step_index(current_speed: f32) -> Option<usize> {
    PLAYBACK_SPEED_STEPS
        .iter()
        .position(|&s| (s - current_speed).abs() < PLAYBACK_SPEED_EPSILON)
}

/// Render overlay stats in the bottom-left corner of the graph.
pub fn render_overlay_stats(ui: &mut egui::Ui, state: &VisualizationState) {
    let local_rect = ui.max_rect();

    egui::Area::new(egui::Id::new("viz_overlay_stats"))
        .fixed_pos(local_rect.left_bottom() + egui::vec2(OVERLAY_MARGIN, -OVERLAY_MARGIN))
        .pivot(egui::Align2::LEFT_BOTTOM)
        .order(egui::Order::Foreground)
        .show(ui.ctx(), |ui| {
            egui::Frame::popup(ui.style())
                .shadow(egui::epaint::Shadow::NONE)
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(format!("Active: {}", state.flow.active_links.len()))
                            .on_hover_text(
                                "Number of network links currently transmitting data.",
                            );
                        ui.separator();
                        ui.label(format!("Total flows: {}", state.flow.total_flows))
                            .on_hover_text(
                                "Cumulative number of flows generated since the simulation started.",
                            );
                    });
                });
        });
}

/// Render node legend in the top-right corner of the graph.
pub fn render_overlay_node_legend(ui: &mut egui::Ui) {
    let local_rect = ui.max_rect();

    egui::Area::new(egui::Id::new("viz_overlay_node_legend"))
        .pivot(egui::Align2::RIGHT_TOP)
        .fixed_pos(local_rect.right_top() + egui::vec2(-OVERLAY_MARGIN, OVERLAY_MARGIN))
        .order(egui::Order::Foreground)
        .show(ui.ctx(), |ui| {
            egui::Frame::popup(ui.style())
                .shadow(egui::epaint::Shadow::NONE)
                .show(ui, |ui| {
                    legend_item_with_image(ui, "Server", IMG_SERVER);
                    legend_item_with_image(ui, "User", IMG_COMPUTER);
                    legend_item_with_image(ui, "Internet", IMG_INTERNET);
                })
                .response
                .on_hover_text("Node types. Size reflects relative traffic activity.");
        });
}

/// Render edge legend in the bottom-right corner of the graph.
pub fn render_overlay_edge_legend(ui: &mut egui::Ui) {
    let local_rect = ui.max_rect();

    egui::Area::new(egui::Id::new("viz_overlay_edge_legend"))
        .pivot(egui::Align2::RIGHT_BOTTOM)
        .fixed_pos(local_rect.right_bottom() + egui::vec2(-OVERLAY_MARGIN, -OVERLAY_MARGIN))
        .order(egui::Order::Foreground)
        .show(ui.ctx(), |ui| {
            egui::Frame::popup(ui.style())
                .shadow(egui::epaint::Shadow::NONE)
                .show(ui, |ui| {
                    legend_item_inline(ui, "Inactive", COLOR_EDGE_INACTIVE);
                    for proto in L7Proto::iter() {
                        legend_item_inline(ui, proto.ui_label(), color_for_protocol(&proto));
                    }
                })
                .response
                .on_hover_text(
                    "Link protocols. Color shows protocol, thickness reflects relative traffic volume.",
                );
        });
}
