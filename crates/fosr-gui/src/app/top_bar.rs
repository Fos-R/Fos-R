//! Top bar rendering: tab navigation, zoom controls, and theme switch.

use crate::shared::constants::colors::COLOR_ERROR;
#[cfg(not(target_arch = "wasm32"))]
use crate::shared::constants::ui::SPACING_SM;
use crate::shared::constants::ui::{
    BUTTON_PADDING, PANEL_INNER_MARGIN, TEXT_SIZE_DEFAULT, ZOOM_MAX, ZOOM_MIN, ZOOM_STEP,
};
use eframe::egui;
use eframe::egui::global_theme_preference_switch;

#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
pub enum CurrentTab {
    #[default]
    Run,
    Configuration,
    About,
}

#[derive(Clone)]
pub struct TopBarState {
    pub current_tab: CurrentTab,
    pub zoom_factor: f32,
    pub has_errors: bool,
}

/// Render the top bar with tabs and utility buttons.
/// Returns the updated TopBarState.
pub fn render_top_bar(ctx: &egui::Context, state: TopBarState) -> TopBarState {
    let mut new_state = state.clone();

    egui::TopBottomPanel::top("top_panel")
        .frame(
            egui::Frame::side_top_panel(&ctx.style())
                .inner_margin(egui::Margin::symmetric(PANEL_INNER_MARGIN.0, PANEL_INNER_MARGIN.1)),
        )
        .show(ctx, |ui| {
            // Add a Menu Bar to host the tabs buttons
            egui::MenuBar::new().ui(ui, |ui| {
                ui.spacing_mut().button_padding =
                    egui::vec2(BUTTON_PADDING.0, BUTTON_PADDING.1);
                let tab_text_size = TEXT_SIZE_DEFAULT;

                let has_errors = state.has_errors;

                // Run tab (combines Live Preview + Generation)
                let run_button =
                    egui::Button::new(egui::RichText::new("Run").size(tab_text_size))
                        .selected(state.current_tab == CurrentTab::Run);

                let response = ui.add_enabled(!has_errors, run_button);

                let response = if has_errors {
                    response.on_disabled_hover_text(
                        "Configuration is invalid. Fix errors in the Configuration tab to enable Run.",
                    )
                } else {
                    response
                        .on_hover_text("Live preview and PCAP generation from the current configuration.")
                };

                if !has_errors && response.clicked() {
                    new_state.current_tab = CurrentTab::Run;
                }

                // Configuration tab
                let label_text = if has_errors {
                    egui::RichText::new("⚠ Configuration")
                        .color(COLOR_ERROR)
                        .size(tab_text_size)
                } else {
                    egui::RichText::new("Configuration").size(tab_text_size)
                };
                if ui
                    .add(
                        egui::Button::new(label_text)
                            .selected(state.current_tab == CurrentTab::Configuration),
                    )
                    .on_hover_text(
                        "Edit the network configuration: hosts, interfaces, and services.",
                    )
                    .clicked()
                {
                    new_state.current_tab = CurrentTab::Configuration;
                };

                // About tab
                if ui
                    .add(
                        egui::Button::new(
                            egui::RichText::new("About").size(tab_text_size),
                        )
                            .selected(state.current_tab == CurrentTab::About),
                    )
                    .on_hover_text("About Fos-R and its authors.")
                    .clicked()
                {
                    new_state.current_tab = CurrentTab::About;
                }

                // Right-align utility buttons so they sit on the opposite side of the tabs
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    // On web, show a fullscreen toggle button
                    #[cfg(target_arch = "wasm32")]
                    {
                        let is_fullscreen = web_sys::window()
                            .and_then(|w| w.document())
                            .and_then(|d| d.fullscreen_element())
                            .is_some();

                        let (icon, tooltip) = if is_fullscreen {
                            (
                                egui_material_icons::icons::ICON_FULLSCREEN_EXIT,
                                "Exit fullscreen",
                            )
                        } else {
                            (
                                egui_material_icons::icons::ICON_FULLSCREEN,
                                "Fullscreen",
                            )
                        };

                        if ui.button(icon).on_hover_text(tooltip).clicked() {
                            if let Some(window) = web_sys::window() {
                                if let Some(document) = window.document() {
                                    if is_fullscreen {
                                        document.exit_fullscreen();
                                    } else if let Some(canvas) =
                                        document.get_element_by_id("fosr_gui_canvas")
                                    {
                                        let _ = canvas.request_fullscreen();
                                    }
                                }
                            }
                        }
                    }

                    #[cfg(not(target_arch = "wasm32"))]
                    ui.add_space(SPACING_SM);

                    // Show the theme switch
                    global_theme_preference_switch(ui);

                    // Zoom controls
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 2.0;
                        if ui
                            .button(egui_material_icons::icons::ICON_ADD)
                            .on_hover_text("Zoom in")
                            .clicked()
                        {
                            let current_zoom = ctx.zoom_factor();
                            let new_zoom = (current_zoom + ZOOM_STEP).min(ZOOM_MAX);
                            ctx.set_zoom_factor(new_zoom);
                            new_state.zoom_factor = new_zoom;
                        }
                        ui.label(format!("{:.0}%", ctx.zoom_factor() * 100.0));
                        if ui
                            .button(egui_material_icons::icons::ICON_REMOVE)
                            .on_hover_text("Zoom out")
                            .clicked()
                        {
                            let current_zoom = ctx.zoom_factor();
                            let new_zoom = (current_zoom - ZOOM_STEP).max(ZOOM_MIN);
                            ctx.set_zoom_factor(new_zoom);
                            new_state.zoom_factor = new_zoom;
                        }
                    });
                });
            });
        });

    new_state
}
