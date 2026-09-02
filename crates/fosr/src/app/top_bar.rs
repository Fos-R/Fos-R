//! Top bar rendering: tab navigation, zoom controls, and theme switch.

use crate::app::{AppTab, FosrApp, ViewState};
use crate::shared::constants::colors::COLOR_ERROR;
use crate::shared::constants::ui::*;
use eframe::egui;
use eframe::egui::global_theme_preference_switch;
use egui_material_icons::icons::{ICON_ADD, ICON_REMOVE};
#[cfg(target_arch = "wasm32")]
use egui_material_icons::icons::{ICON_FULLSCREEN, ICON_FULLSCREEN_EXIT};

// /// Available tabs in the Fos-R application.
// #[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
// pub enum AppTab {
//     #[default]
//     Run,
//     Configuration,
//     About,
// }

// /// State passed between the top bar and the main app for rendering.
// #[derive(Clone)]
// pub struct TopBarState {
//     pub current_tab: AppTab,
//     pub zoom_factor: f32,
//     pub has_errors: bool,
//     pub has_hosts: bool,
// }

/// Renders a tab button with consistent styling.
fn render_tab_button(
    ui: &mut egui::Ui,
    text_size: f32,
    label: &str,
    state: &mut FosrApp,
    tab: AppTab,
    is_selected: bool,
    is_enabled: bool,
    tooltip: &str,
    disabled_tooltip: &str,
) {
    let button =
        egui::Button::new(egui::RichText::new(label).size(text_size)).selected(is_selected);
    let response = ui.add_enabled(is_enabled, button);

    let response = if is_enabled {
        response.on_hover_text(tooltip)
    } else {
        response.on_disabled_hover_text(disabled_tooltip)
    };

    if is_enabled && response.clicked() {
        match tab {
            AppTab::Run => state.change_view(ViewState::GraphTab),
            AppTab::Configuration => state.change_view(ViewState::ConfigTab),
        }
    }
}

/// Renders the Configuration tab with error indicator when config is invalid.
fn render_config_tab_button(
    ui: &mut egui::Ui,
    state: &mut FosrApp,
    text_size: f32,
    has_errors: bool,
    is_selected: bool,
) {
    let label = if has_errors {
        egui::RichText::new("⚠ Network Editor")
            .color(COLOR_ERROR)
            .size(text_size)
    } else {
        egui::RichText::new("Network Editor").size(text_size)
    };

    let button = egui::Button::new(label).selected(is_selected);

    if ui
        .add(button)
        .on_hover_text("Edit the network: hosts, interfaces, and services.")
        .clicked()
    {
        state.change_view(ViewState::ConfigTab);
    }
}

/// Renders all tab buttons.
pub fn render_tab_buttons(ui: &mut egui::Ui, state: &mut FosrApp) {
    let text_size = TEXT_SIZE_DEFAULT;
    let has_errors = state.has_errors_in_config();

    // Run tab (disabled when config has errors or no hosts)
    let run_enabled = !has_errors && state.has_hosts_in_config();
    render_tab_button(
        ui,
        text_size,
        "View & Run",
        state,
        AppTab::Run,
        state.get_current_tab() == Some(AppTab::Run),
        run_enabled,
        "Live preview and PCAP generation for the current network.",
        if has_errors {
            "Configuration is invalid. Fix errors in the Configuration tab to enable Run."
        } else {
            "No hosts in the configuration. Add at least one host to enable Run."
        },
    );

    // Configuration tab (always enabled, shows warning icon on errors)
    render_config_tab_button(
        ui,
        state,
        text_size,
        has_errors,
        state.get_current_tab() == Some(AppTab::Configuration),
    );

    // TODO: modale
    // About tab
    // render_tab_button(
    //     ui,
    //     text_size,
    //     "About",
    //     state,
    //     AppTab::About,
    //     state.get_current_tab() == Some(AppTab::About),
    //     true,
    //     "About Fos-R and its authors.",
    //     "",
    // );
}

/// Renders zoom in/out controls.
fn render_zoom_controls(ui: &mut egui::Ui, ctx: &egui::Context) {
    let mut new_zoom = ctx.zoom_factor();

    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = SPACING_XS;

        if ui.button(ICON_ADD).on_hover_text("Zoom in").clicked() {
            new_zoom = (new_zoom + ZOOM_STEP).min(ZOOM_MAX);
            ctx.set_zoom_factor(new_zoom);
        }

        ui.label(format!("{:.0}%", (new_zoom - ZOOM_OFFSET) * 100.0));

        if ui.button(ICON_REMOVE).on_hover_text("Zoom out").clicked() {
            new_zoom = (new_zoom - ZOOM_STEP).max(ZOOM_MIN);
            ctx.set_zoom_factor(new_zoom);
        }
    });
}

/// Returns true if the browser is currently in fullscreen mode.
#[cfg(target_arch = "wasm32")]
fn is_fullscreen() -> bool {
    web_sys::window()
        .and_then(|w| w.document())
        .and_then(|d| d.fullscreen_element())
        .is_some()
}

/// Toggles browser fullscreen mode on or off.
#[cfg(target_arch = "wasm32")]
fn toggle_fullscreen(is_fullscreen: bool) {
    let Some(window) = web_sys::window() else {
        return;
    };
    let Some(document) = window.document() else {
        return;
    };

    if is_fullscreen {
        document.exit_fullscreen();
    } else if let Some(canvas) = document.get_element_by_id("fosr_gui_canvas") {
        let _ = canvas.request_fullscreen();
    }
}

/// Renders the fullscreen toggle button for web builds.
#[cfg(target_arch = "wasm32")]
fn render_fullscreen_toggle(ui: &mut egui::Ui) {
    let fullscreen = is_fullscreen();
    let (icon, tooltip) = if fullscreen {
        (ICON_FULLSCREEN_EXIT, "Exit fullscreen")
    } else {
        (ICON_FULLSCREEN, "Fullscreen")
    };

    if ui.button(icon).on_hover_text(tooltip).clicked() {
        toggle_fullscreen(fullscreen);
    }
}

/// Renders utility buttons on the right side of the top bar.
pub fn render_utility_buttons(ui: &mut egui::Ui, ctx: &egui::Context, state: &mut FosrApp) {
    #[cfg(target_arch = "wasm32")]
    render_fullscreen_toggle(ui);

    #[cfg(not(target_arch = "wasm32"))]
    ui.add_space(SPACING_SM);

    global_theme_preference_switch(ui);
    render_zoom_controls(ui, ctx);

    let button = egui::Button::new(egui::RichText::new("About").size(TEXT_SIZE_SM));

    if ui.add(button).on_hover_text("About Fos-R").clicked() {
        state.extra_modals.about = true;
    }
}
