//! Startup modal for choosing configuration source (templates or import).

use crate::config_templates::{TEMPLATES, load_empty_config, load_template};
#[cfg(target_arch = "wasm32")]
use crate::shared::config::file_ops::poll_file_import;
use crate::shared::config::file_ops::trigger_file_import;
use crate::shared::config::state::{ConfigFileState, StartupModalStep};
use crate::shared::constants::colors::COLOR_TEXT_MUTED;
use crate::shared::constants::ui::{
    ICON_SIZE_LG, MODAL_WIDTH_MD, SPACING_LG, SPACING_SM, SPACING_XL, SPACING_XS,
    STARTUP_CARD_INITIAL_HEIGHT, STARTUP_CARD_TEMPLATE_HEIGHT, STARTUP_COLUMNS_INITIAL,
    STARTUP_COLUMNS_TEMPLATES, TEXT_SIZE_LG, TEXT_SIZE_SM,
};
use eframe::egui;
use egui_material_icons::icons::{ICON_ARROW_BACK, ICON_EDIT, ICON_LAN, ICON_UPLOAD_FILE};

/// Builds the frame style for a startup card based on hover state.
fn card_frame_for_hover(ui: &egui::Ui, is_hovered: bool) -> egui::Frame {
    let fill = if is_hovered {
        ui.style().visuals.widgets.hovered.bg_fill
    } else {
        ui.style().visuals.widgets.inactive.bg_fill
    };
    egui::Frame::group(ui.style()).fill(fill)
}

/// Renders the centered content inside a startup card (icon, title, description).
fn render_card_content(ui: &mut egui::Ui, icon: &str, title: &str, description: &str) {
    // Disable text selection so the whole card acts as a single clickable area
    ui.style_mut().interaction.selectable_labels = false;
    ui.set_width(ui.available_width());
    ui.set_height(ui.available_height());

    ui.vertical_centered(|ui| {
        ui.add_space(SPACING_LG);
        ui.label(egui::RichText::new(icon).size(ICON_SIZE_LG));
        ui.add_space(SPACING_SM);
        ui.strong(egui::RichText::new(title).size(TEXT_SIZE_LG));
        ui.add_space(SPACING_XS);
        ui.label(
            egui::RichText::new(description)
                .size(TEXT_SIZE_SM)
                .color(COLOR_TEXT_MUTED),
        );
        ui.add_space(SPACING_LG);
    });
}

/// A clickable card with icon, title and description.
/// Returns true if the card was clicked.
fn startup_card(
    ui: &mut egui::Ui,
    icon: &str,
    title: &str,
    description: &str,
    min_height: f32,
) -> bool {
    let desired_size = egui::vec2(ui.available_width(), min_height);
    let (rect, response) = ui.allocate_exact_size(desired_size, egui::Sense::click());

    let frame = card_frame_for_hover(ui, response.hovered());
    ui.scope_builder(egui::UiBuilder::new().max_rect(rect), |ui| {
        frame.show(ui, |ui| {
            render_card_content(ui, icon, title, description);
        });
    });

    if response.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }

    response.clicked()
}

/// Renders the startup modal for choosing a configuration source.
pub fn render_startup_modal(ctx: &egui::Context, state: &mut ConfigFileState) {
    match state.modal_state {
        StartupModalStep::Initial => render_initial_modal(ctx, state),
        StartupModalStep::TemplateSelection => render_template_selection_modal(ctx, state),
    }
}

/// Renders the initial modal with options to use templates or import a file.
fn render_initial_modal(ctx: &egui::Context, state: &mut ConfigFileState) {
    // Use the same modal ID as template selection to avoid flicker when transitioning
    egui::Modal::new(egui::Id::new("startup_modal")).show(ctx, |ui| {
        ui.set_width(MODAL_WIDTH_MD);
        ui.heading("Welcome to Fos-R");
        ui.add_space(SPACING_SM);
        ui.label("Select a network to get started");
        ui.add_space(SPACING_XL);

        ui.columns(STARTUP_COLUMNS_INITIAL, |cols| {
            // Left: empty config
            if startup_card(
                &mut cols[0],
                ICON_EDIT,
                "Empty network",
                "Start from scratch with an empty network",
                STARTUP_CARD_INITIAL_HEIGHT,
            ) {
                load_empty_config(state);
            }

            // Middle: default config (templates)
            if startup_card(
                &mut cols[1],
                ICON_LAN,
                "Default network",
                "Choose from presets of different network types",
                STARTUP_CARD_INITIAL_HEIGHT,
            ) {
                state.modal_state = StartupModalStep::TemplateSelection;
            }

            // Right: import file
            if startup_card(
                &mut cols[2],
                ICON_UPLOAD_FILE,
                "Import YAML file",
                "Load a network configuration from a file",
                STARTUP_CARD_INITIAL_HEIGHT,
            ) {
                trigger_file_import(state, cols[2].ctx());
            }
        });

        #[cfg(target_arch = "wasm32")]
        poll_file_import(state);
    });
}

/// Renders the template selection modal with preset network configurations.
fn render_template_selection_modal(ctx: &egui::Context, state: &mut ConfigFileState) {
    // Use the same modal ID as initial modal to avoid flicker when transitioning
    egui::Modal::new(egui::Id::new("startup_modal")).show(ctx, |ui| {
        ui.set_width(MODAL_WIDTH_MD);

        // Header with back button
        ui.horizontal(|ui| {
            if ui.button(ICON_ARROW_BACK).on_hover_text("Back").clicked() {
                state.modal_state = StartupModalStep::Initial;
            }
            ui.heading("Choose a template");
        });

        ui.add_space(SPACING_XL);

        // Grid of template cards
        ui.columns(STARTUP_COLUMNS_TEMPLATES, |cols| {
            for (i, template) in TEMPLATES.iter().enumerate() {
                if startup_card(
                    &mut cols[i % STARTUP_COLUMNS_TEMPLATES],
                    template.icon,
                    template.title,
                    template.description,
                    STARTUP_CARD_TEMPLATE_HEIGHT,
                ) {
                    load_template(state, template);
                }
            }
        });
    });
}
