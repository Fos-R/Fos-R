//! Network tab: toggles between visual mode and YAML editor.

use crate::app::FosrApp;
use crate::config_editor::toolbar::render_configuration_toolbar;
use crate::config_editor::{host, host_validation, yaml_editor};
use crate::shared::config::file_ops::load_config_file_contents;
use crate::shared::config::state::ConfigFileState;
use crate::shared::constants::colors::COLOR_ERROR;
use crate::shared::constants::ui::{SPACING_MD, TEXT_EDIT_DEFAULT_ROWS};
use crate::shared::widgets::helpers::{
    render_optional_string_input, render_optional_text_area, required_label,
};
use eframe::egui;
use egui_material_icons::icons::ICON_WARNING;
use fosr_lib::network::NetworkYaml;

/// The main tab component
pub fn render_configuration_tab(ui: &mut egui::Ui, state: &mut FosrApp) {
    // Eagerly load config file contents when a file is selected
    load_config_file_contents(&mut state.config_file_state);

    // Toolbar stays fixed above the scroll area
    render_configuration_toolbar(ui, state);

    let file_state = &mut state.config_file_state;
    render_parse_error_banner(ui, file_state);

    ui.separator();

    egui::ScrollArea::vertical().show(ui, |ui| {
        if !state.configuration_tab_state.is_code_mode {
            // Visual mode
            if let Some(model) = file_state.get_mut_config_model() {
                host::render_hosts_section(ui, model);
                ui.separator();
                let meta_id = ui.make_persistent_id("metadata_section");
                egui::collapsing_header::CollapsingState::load_with_default_open(
                    ui.ctx(),
                    meta_id,
                    false,
                )
                .show_header(ui, |ui| {
                    ui.heading("Metadata");
                })
                .body(|ui| {
                    render_metadata_section(ui, model);
                });
            }

            sync_model_to_yaml_state(file_state);
        } else {
            yaml_editor::render_yaml_editor(ui, file_state);
        }

        // Update error flag (parse errors + host validation errors)
        file_state.has_errors = file_state.config_error.is_some()
            || file_state
                .get_config_model()
                .as_ref()
                .is_some_and(host_validation::has_model_errors);
    });
}

/// Sync model state to YAML content and update dirty flag.
///
/// Serializes the current model to YAML string and compares against
/// the clean snapshot to detect unsaved changes.
fn sync_model_to_yaml_state(state: &mut ConfigFileState) {
    let had_error = state.config_error.is_some();
    state.sync_model_to_yaml();

    // If serialization succeeded, update dirty flag by comparing with cached snapshot YAML
    if !had_error
        && state.config_error.is_none()
        && let Some(model_yaml) = &state.config_file_content
        && let Some(snap_yaml) = &state.clean_snapshot
    {
        state.is_dirty = *model_yaml != *snap_yaml;
    }
}

/// Displays a YAML parse error banner below the toolbar, if any.
fn render_parse_error_banner(ui: &mut egui::Ui, state: &ConfigFileState) {
    if let Some(err) = &state.config_error {
        ui.separator();
        ui.colored_label(COLOR_ERROR, format!("{} YAML parsing failed", ICON_WARNING));
        ui.colored_label(COLOR_ERROR, err);
    }
}

/// Metadata rendering
fn render_metadata_section(ui: &mut egui::Ui, model: &mut NetworkYaml) {
    ui.add_space(SPACING_MD);

    // Title
    ui.horizontal(|ui| {
        required_label(ui, "Title");
        ui.text_edit_singleline(&mut model.metadata.title);
    });

    render_optional_text_area(
        ui,
        "Description",
        &mut model.metadata.desc,
        "Optional description",
        TEXT_EDIT_DEFAULT_ROWS,
    );

    render_optional_string_input(ui, "Author", &mut model.metadata.author, "Jane Doe");

    render_optional_string_input(ui, "Version", &mut model.metadata.version, "0.1.0");
}
