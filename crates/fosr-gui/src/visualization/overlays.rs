//! Graph overlay UI: control buttons, stats display, and legends for nodes/edges.

use super::shapes::{
    COLOR_DNS, COLOR_HTTP, COLOR_HTTPS, COLOR_INACTIVE, COLOR_OTHER, COLOR_SMTP, COLOR_SSH,
    ICON_TINT_DARK, ICON_TINT_LIGHT,
};
use super::state::{STOP_BUTTON_COLOR, VisualizationState};
use eframe::egui;

/// Helper to render a single legend item inline (for edges)
fn legend_item_inline(ui: &mut egui::Ui, label: &str, color: egui::Color32) {
    ui.horizontal(|ui| {
        let rect = ui.allocate_space(egui::vec2(12.0, 12.0)).1;
        let painter = ui.painter();
        painter.circle_filled(rect.center(), 6.0, color);
        ui.add_space(-2.0);
        ui.label(label);
    });
}

/// Helper to render a legend item with an image (for nodes)
fn legend_item_with_image(ui: &mut egui::Ui, label: &str, image: egui::ImageSource) {
    ui.horizontal(|ui| {
        let tint = if ui.style().visuals.dark_mode {
            ICON_TINT_DARK
        } else {
            ICON_TINT_LIGHT
        };
        ui.add(
            egui::Image::new(image)
                .fit_to_exact_size(egui::vec2(20.0, 20.0))
                .tint(tint),
        );
        ui.add_space(-2.0);
        ui.label(label);
    });
}

/// Render overlay buttons in the top-left corner of the graph
pub fn render_overlay_buttons(ui: &mut egui::Ui, state: &mut VisualizationState) {
    let local_rect = ui.max_rect();

    egui::Area::new(egui::Id::new("viz_overlay_buttons"))
        .fixed_pos(local_rect.left_top() + egui::vec2(4.0, 4.0))
        .order(egui::Order::Foreground)
        .show(ui.ctx(), |ui| {
            egui::Frame::popup(ui.style())
                .shadow(egui::epaint::Shadow::NONE)
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        if !state.visualization_running {
                            // Play / Continue: resume without resetting flow counts
                            let play_text = if state.user_has_started {
                                "Continue"
                            } else {
                                "Start"
                            };
                            let accent = ui.visuals().selection.bg_fill;
                            let play_button = egui::Button::new(egui::RichText::new(format!(
                                "{} {}",
                                egui_material_icons::icons::ICON_PLAY_ARROW,
                                play_text
                            )))
                            .fill(accent);
                            if ui.add(play_button).clicked() {
                                state.user_has_started = true;
                                // Pass the user config if loaded, otherwise None (uses default BN model)
                                let config = state.config_content.clone();
                                let speed = state.speed.clone();
                                if let Err(e) =
                                    state.start_visualization(config.as_deref(), speed, false)
                                {
                                    log::error!("Failed to start flow streamer: {}", e);
                                }
                            }
                            // Restart: reset all flow counts and start fresh
                            // Only visible after the user has started at least once
                            if state.user_has_started {
                                if ui
                                    .button(egui_material_icons::icons::ICON_RESTART_ALT)
                                    .on_hover_text("Restart")
                                    .clicked()
                                {
                                    let config = state.config_content.clone();
                                    let speed = state.speed.clone();
                                    if let Err(e) =
                                        state.start_visualization(config.as_deref(), speed, true)
                                    {
                                        log::error!("Failed to start flow streamer: {}", e);
                                    }
                                }
                            }
                        } else {
                            let stop_button = egui::Button::new(egui::RichText::new(format!(
                                "{} Stop",
                                egui_material_icons::icons::ICON_STOP
                            )))
                            .fill(STOP_BUTTON_COLOR);
                            if ui.add(stop_button).clicked() {
                                state.stop_visualization();
                            }
                        }
                        if ui
                            .button(egui_material_icons::icons::ICON_FIT_SCREEN)
                            .on_hover_text("Fit to screen")
                            .clicked()
                        {
                            state.reset_view_requested = true;
                        }
                        if ui
                            .button(egui_material_icons::icons::ICON_IMAGE)
                            .on_hover_text("Export as PNG")
                            .clicked()
                        {
                            state.export_state = super::state::ExportState::HidingOverlays;
                        }

                        ui.separator();

                        // Playback speed: −/+ buttons with discrete steps
                        let speed_steps: &[f32] = &[0.25, 0.5, 0.75, 1.0, 1.5, 2.0, 3.0, 4.0];
                        // Speed is an Arc, we cannot use it directly with the buttons,
                        // we need to read and write its value manually.
                        let mut speed_value = *state.speed.read().unwrap();
                        let current_idx = speed_steps
                            .iter()
                            .position(|&s| (s - speed_value).abs() < 0.01);

                        if ui
                            .button(egui_material_icons::icons::ICON_REMOVE)
                            .on_hover_text("Slow down")
                            .clicked()
                        {
                            if let Some(idx) = current_idx {
                                if idx > 0 {
                                    speed_value = speed_steps[idx - 1];
                                    *state.speed.write().unwrap() = speed_value;
                                }
                            }
                        }
                        ui.label(format!("{:.1}x", speed_value)).on_hover_text(
                            "Playback speed — controls how fast network flows are simulated",
                        );
                        if ui
                            .button(egui_material_icons::icons::ICON_ADD)
                            .on_hover_text("Speed up")
                            .clicked()
                        {
                            if let Some(idx) = current_idx {
                                if idx < speed_steps.len() - 1 {
                                    speed_value = speed_steps[idx + 1];
                                    *state.speed.write().unwrap() = speed_value;
                                }
                            }
                        }
                    });
                });
        });
}

/// Render overlay stats in the bottom-left corner of the graph
pub fn render_overlay_stats(ui: &mut egui::Ui, state: &VisualizationState) {
    let local_rect = ui.max_rect();

    egui::Area::new(egui::Id::new("viz_overlay_stats"))
        .fixed_pos(local_rect.left_bottom() + egui::vec2(4.0, 0.0))
        .pivot(egui::Align2::LEFT_BOTTOM)
        .order(egui::Order::Foreground)
        .show(ui.ctx(), |ui| {
            egui::Frame::popup(ui.style())
                .shadow(egui::epaint::Shadow::NONE)
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(format!("Active: {}", state.active_links.len()))
                            .on_hover_text(
                                "Number of network links currently transmitting data.",
                            );
                        ui.separator();
                        ui.label(format!("Total flows: {}", state.total_flows))
                            .on_hover_text(
                                "Cumulative number of flows generated since the simulation started.",
                            );
                    });
                });
        });
}

/// Render node legend in the top-right corner of the graph
pub fn render_overlay_node_legend(ui: &mut egui::Ui) {
    let local_rect = ui.max_rect();

    egui::Area::new(egui::Id::new("viz_overlay_node_legend"))
        .pivot(egui::Align2::RIGHT_TOP)
        .fixed_pos(local_rect.right_top() + egui::vec2(-4.0, 4.0))
        .order(egui::Order::Foreground)
        .show(ui.ctx(), |ui| {
            egui::Frame::popup(ui.style())
                .shadow(egui::epaint::Shadow::NONE)
                .show(ui, |ui| {
                    legend_item_with_image(
                        ui,
                        "Server",
                        egui::include_image!("../../assets/server.png"),
                    );
                    legend_item_with_image(
                        ui,
                        "User",
                        egui::include_image!("../../assets/computer.png"),
                    );
                    legend_item_with_image(
                        ui,
                        "Internet",
                        egui::include_image!("../../assets/internet.png"),
                    );
                })
                .response
                .on_hover_text("Node types. Size reflects relative traffic activity.");
        });
}

/// Render edge legend in the bottom-right corner of the graph
pub fn render_overlay_edge_legend(ui: &mut egui::Ui) {
    let local_rect = ui.max_rect();

    egui::Area::new(egui::Id::new("viz_overlay_edge_legend"))
        .pivot(egui::Align2::RIGHT_BOTTOM)
        .fixed_pos(local_rect.right_bottom() + egui::vec2(-4.0, -4.0))
        .order(egui::Order::Foreground)
        .show(ui.ctx(), |ui| {
            egui::Frame::popup(ui.style())
                .shadow(egui::epaint::Shadow::NONE)
                .show(ui, |ui| {
                    legend_item_inline(ui, "Inactive", COLOR_INACTIVE);
                    legend_item_inline(ui, "HTTP", COLOR_HTTP);
                    legend_item_inline(ui, "HTTPS", COLOR_HTTPS);
                    legend_item_inline(ui, "SSH", COLOR_SSH);
                    legend_item_inline(ui, "DNS", COLOR_DNS);
                    legend_item_inline(ui, "SMTP", COLOR_SMTP);
                    legend_item_inline(ui, "Other", COLOR_OTHER);
                })
                .response
                .on_hover_text(
                    "Link protocols. Color shows protocol, thickness reflects relative traffic volume.",
                );
        });
}
