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

/// Renders a tab button with consistent styling.
///
/// Returns `Some(clicked_tab)` if the button was clicked, `None` otherwise.
/// Handles both enabled and disabled states with appropriate tooltips.
fn render_tab_button(
    ui: &mut egui::Ui,
    text_size: f32,
    label: &str,
    tab: CurrentTab,
    is_selected: bool,
    is_enabled: bool,
    tooltip: &str,
    disabled_tooltip: &str,
) -> Option<CurrentTab> {
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
) -> Option<CurrentTab> {
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
        Some(CurrentTab::Configuration)
    } else {
        None
    }
}

/// Renders all tab buttons and returns the newly selected tab if changed.
fn render_tab_buttons(
    ui: &mut egui::Ui,
    state: &TopBarState,
) -> Option<CurrentTab> {
    let text_size = TEXT_SIZE_DEFAULT;
    let has_errors = state.has_errors;

    // Run tab (disabled when config has errors)
    if let Some(tab) = render_tab_button(
        ui,
        text_size,
        "Run",
        CurrentTab::Run,
        state.current_tab == CurrentTab::Run,
        !has_errors,
        "Live preview and PCAP generation from the current configuration.",
        "Configuration is invalid. Fix errors in the Configuration tab to enable Run.",
    ) {
        return Some(tab);
    }

    // Configuration tab (always enabled, shows warning icon on errors)
    if let Some(tab) = render_config_tab_button(ui, text_size, has_errors, state.current_tab == CurrentTab::Configuration) {
        return Some(tab);
    }

    // About tab
    if let Some(tab) = render_tab_button(
        ui,
        text_size,
        "About",
        CurrentTab::About,
        state.current_tab == CurrentTab::About,
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
        ui.spacing_mut().item_spacing.x = 2.0;

        if ui
            .button(egui_material_icons::icons::ICON_ADD)
            .on_hover_text("Zoom in")
            .clicked()
        {
            new_zoom = (new_zoom + ZOOM_STEP).min(ZOOM_MAX);
            ctx.set_zoom_factor(new_zoom);
        }

        ui.label(format!("{:.0}%", new_zoom * 100.0));

        if ui
            .button(egui_material_icons::icons::ICON_REMOVE)
            .on_hover_text("Zoom out")
            .clicked()
        {
            new_zoom = (new_zoom - ZOOM_STEP).max(ZOOM_MIN);
            ctx.set_zoom_factor(new_zoom);
        }
    });

    new_zoom
}

#[cfg(target_arch = "wasm32")]
fn is_fullscreen() -> bool {
    web_sys::window()
        .and_then(|w| w.document())
        .and_then(|d| d.fullscreen_element())
        .is_some()
}

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

#[cfg(target_arch = "wasm32")]
fn render_fullscreen_toggle(ui: &mut egui::Ui) {
    let fullscreen = is_fullscreen();
    let (icon, tooltip) = if fullscreen {
        (egui_material_icons::icons::ICON_FULLSCREEN_EXIT, "Exit fullscreen")
    } else {
        (egui_material_icons::icons::ICON_FULLSCREEN, "Fullscreen")
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

// -----------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------

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
                ui.spacing_mut().button_padding = egui::vec2(BUTTON_PADDING.0, BUTTON_PADDING.1);

                if let Some(tab) = render_tab_buttons(ui, &state) {
                    new_state.current_tab = tab;
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    render_utility_buttons(ui, ctx, &mut new_state);
                });
            });
        });

    new_state
}
