//! Top bar rendering: tab navigation, zoom controls, and theme switch.

use crate::shared::constants::colors::COLOR_ERROR;
#[cfg(not(target_arch = "wasm32"))]
use crate::shared::constants::ui::SPACING_SM;
use crate::shared::constants::ui::{
    SPACING_XS, TAB_BUTTON_PADDING, PANEL_INNER_MARGIN, TEXT_SIZE_DEFAULT, ZOOM_MAX, ZOOM_MIN,
    ZOOM_OFFSET, ZOOM_STEP,
};
use eframe::egui;
use egui_material_icons::icons::{ICON_ADD, ICON_REMOVE};
#[cfg(target_arch = "wasm32")]
use egui_material_icons::icons::{ICON_FULLSCREEN_EXIT, ICON_FULLSCREEN};
use eframe::egui::global_theme_preference_switch;

/// Available tabs in the Fos-R application.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
pub enum AppTab {
    #[default]
    Run,
    Configuration,
    About,
}

/// State passed between the top bar and the main app for rendering.
#[derive(Clone)]
pub struct TopBarState {
    pub current_tab: AppTab,
    pub zoom_factor: f32,
    pub has_errors: bool,
    pub has_hosts: bool,
}

/// Renders a tab button with consistent styling.
///
/// Returns `Some(clicked_tab)` if the button was clicked, `None` otherwise.
/// Handles both enabled and disabled states with appropriate tooltips.
fn render_tab_button(
    ui: &mut egui::Ui,
    text_size: f32,
    label: &str,
    tab: AppTab,
    is_selected: bool,
    is_enabled: bool,
    tooltip: &str,
    disabled_tooltip: &str,
) -> Option<AppTab> {
    let button = egui::Button::new(egui::RichText::new(label).size(text_size)).selected(is_selected);
    let response = ui.add_enabled(is_enabled, button);

    let response = if is_enabled {
        response.on_hover_text(tooltip)
    } else {
        response.on_disabled_hover_text(disabled_tooltip)
    };

    if is_enabled && response.clicked() {
        Some(tab)
    } else {
        None
    }
}

/// Renders the Configuration tab with error indicator when config is invalid.
fn render_config_tab_button(
    ui: &mut egui::Ui,
    text_size: f32,
    has_errors: bool,
    is_selected: bool,
) -> Option<AppTab> {
    let label = if has_errors {
        egui::RichText::new("⚠ Configuration")
            .color(COLOR_ERROR)
            .size(text_size)
    } else {
        egui::RichText::new("Configuration").size(text_size)
    };

    let button = egui::Button::new(label).selected(is_selected);

    if ui
        .add(button)
        .on_hover_text("Edit the network configuration: hosts, interfaces, and services.")
        .clicked()
    {
        Some(AppTab::Configuration)
    } else {
        None
    }
}

/// Renders all tab buttons and returns the newly selected tab if changed.
fn render_tab_buttons(
    ui: &mut egui::Ui,
    state: &TopBarState,
) -> Option<AppTab> {
    let text_size = TEXT_SIZE_DEFAULT;
    let has_errors = state.has_errors;

    // Run tab (disabled when config has errors or no hosts)
    let run_enabled = !has_errors && state.has_hosts;
    if let Some(tab) = render_tab_button(
        ui,
        text_size,
        "Run",
        AppTab::Run,
        state.current_tab == AppTab::Run,
        run_enabled,
        "Live preview and PCAP generation from the current configuration.",
        if has_errors {
            "Configuration is invalid. Fix errors in the Configuration tab to enable Run."
        } else {
            "No hosts in the configuration. Add at least one host to enable Run."
        },
    ) {
        return Some(tab);
    }

    // Configuration tab (always enabled, shows warning icon on errors)
    if let Some(tab) = render_config_tab_button(ui, text_size, has_errors, state.current_tab == AppTab::Configuration) {
        return Some(tab);
    }

    // About tab
    if let Some(tab) = render_tab_button(
        ui,
        text_size,
        "About",
        AppTab::About,
        state.current_tab == AppTab::About,
        true,
        "About Fos-R and its authors.",
        "",
    ) {
        return Some(tab);
    }

    None
}

/// Renders zoom in/out controls and returns the updated zoom factor.
fn render_zoom_controls(ui: &mut egui::Ui, ctx: &egui::Context) -> f32 {
    let mut new_zoom = ctx.zoom_factor();

    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = SPACING_XS;

        if ui
            .button(ICON_ADD)
            .on_hover_text("Zoom in")
            .clicked()
        {
            new_zoom = (new_zoom + ZOOM_STEP).min(ZOOM_MAX);
            ctx.set_zoom_factor(new_zoom);
        }

        ui.label(format!("{:.0}%", (new_zoom - ZOOM_OFFSET) * 100.0));

        if ui
            .button(ICON_REMOVE)
            .on_hover_text("Zoom out")
            .clicked()
        {
            new_zoom = (new_zoom - ZOOM_STEP).max(ZOOM_MIN);
            ctx.set_zoom_factor(new_zoom);
        }
    });

    new_zoom
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
    let Some(window) = web_sys::window() else { return };
    let Some(document) = window.document() else { return };

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
fn render_utility_buttons(ui: &mut egui::Ui, ctx: &egui::Context, state: &mut TopBarState) {
    #[cfg(target_arch = "wasm32")]
    render_fullscreen_toggle(ui);

    #[cfg(not(target_arch = "wasm32"))]
    ui.add_space(SPACING_SM);

    global_theme_preference_switch(ui);
    state.zoom_factor = render_zoom_controls(ui, ctx);
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
            egui::MenuBar::new().ui(ui, |ui| {
                // Scoped padding for tab buttons only
                ui.scope(|ui| {
                    ui.spacing_mut().button_padding = egui::vec2(TAB_BUTTON_PADDING.0, TAB_BUTTON_PADDING.1);
                    if let Some(tab) = render_tab_buttons(ui, &state) {
                        new_state.current_tab = tab;
                    }
                });

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    render_utility_buttons(ui, ctx, &mut new_state);
                });
            });
        });

    new_state
}
