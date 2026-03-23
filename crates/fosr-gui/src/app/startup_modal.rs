//! Startup modal for choosing configuration source (templates or import).

use crate::config_templates::{all_templates, load_template_by_id};
use crate::shared::colors::COLOR_TEXT_MUTED;
#[cfg(target_arch = "wasm32")]
use crate::shared::configuration_file::poll_file_import;
use crate::shared::configuration_file::{
    ConfigurationFileState, StartupModalState, trigger_file_import,
};
use crate::shared::ui_constants::{
    ICON_SIZE_LG, MODAL_WIDTH_MD, SPACING_LG, SPACING_SM, SPACING_XL, SPACING_XS,
    STARTUP_CARD_HEIGHT, STARTUP_COLUMNS_INITIAL, STARTUP_COLUMNS_TEMPLATES, TEXT_SIZE_LG,
    TEXT_SIZE_SM,
};
use eframe::egui;

/// A clickable card with icon, title and description. Returns true if clicked.
fn startup_card(ui: &mut egui::Ui, icon: &str, title: &str, description: &str) -> bool {
    // Reserve the full width and detect hover/click on the whole area
    let desired_size = egui::vec2(ui.available_width(), STARTUP_CARD_HEIGHT);
    let (rect, response) = ui.allocate_exact_size(desired_size, egui::Sense::click());

    // Choose fill color based on hover
    let fill = if response.hovered() {
        ui.style().visuals.widgets.hovered.bg_fill
    } else {
        ui.style().visuals.widgets.inactive.bg_fill
    };

    let frame = egui::Frame::group(ui.style()).fill(fill);
    ui.scope_builder(egui::UiBuilder::new().max_rect(rect), |ui| {
        frame.show(ui, |ui| {
            // Prevent child labels/icons from showing their own hover cursor and
            // highlight, so the entire card acts as a single clickable area.
            ui.style_mut().interaction.selectable_labels = false;
            ui.set_width(ui.available_width());
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
        });
    });

    if response.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }

    response.clicked()
}

pub fn render_startup_modal(ctx: &egui::Context, state: &mut ConfigurationFileState) {
    match state.modal_state {
        StartupModalState::Initial => render_initial_modal(ctx, state),
        StartupModalState::TemplateSelection => render_template_selection_modal(ctx, state),
    }
}

fn render_initial_modal(ctx: &egui::Context, state: &mut ConfigurationFileState) {
    // Use the same modal ID as template selection to avoid flicker when transitioning
    egui::Modal::new(egui::Id::new("startup_modal")).show(ctx, |ui| {
        ui.set_width(MODAL_WIDTH_MD);
        ui.heading("Welcome to Fos-R");
        ui.add_space(SPACING_SM);
        ui.label("Choose a configuration to get started:");
        ui.add_space(SPACING_XL);

        ui.columns(STARTUP_COLUMNS_INITIAL, |cols| {
            // Left: default config
            if startup_card(
                &mut cols[0],
                egui_material_icons::icons::ICON_LAN,
                "Default configuration",
                "Choose from preset templates\nfor different network types",
            ) {
                state.modal_state = StartupModalState::TemplateSelection;
            }

            // Right: import file
            if startup_card(
                &mut cols[1],
                egui_material_icons::icons::ICON_UPLOAD_FILE,
                "Import YAML file",
                "Load your own network\nconfiguration from a file",
            ) {
                trigger_file_import(state, cols[1].ctx());
            }
        });

        #[cfg(target_arch = "wasm32")]
        poll_file_import(state);
    });
}

fn render_template_selection_modal(ctx: &egui::Context, state: &mut ConfigurationFileState) {
    // Use the same modal ID as initial modal to avoid flicker when transitioning
    egui::Modal::new(egui::Id::new("startup_modal")).show(ctx, |ui| {
        ui.set_width(MODAL_WIDTH_MD);

        // Header with back button
        ui.horizontal(|ui| {
            if ui
                .button(egui_material_icons::icons::ICON_ARROW_BACK)
                .on_hover_text("Back")
                .clicked()
            {
                state.modal_state = StartupModalState::Initial;
            }
            ui.heading("Choose a template");
        });

        ui.add_space(SPACING_XL);

        // Grid of template cards
        let templates = all_templates();
        ui.columns(STARTUP_COLUMNS_TEMPLATES, |cols| {
            for (i, template) in templates.iter().enumerate() {
                if startup_card(
                    &mut cols[i % STARTUP_COLUMNS_TEMPLATES],
                    template.icon,
                    template.title,
                    template.description,
                ) {
                    load_template_by_id(state, template.id);
                }
            }
        });
    });
}
