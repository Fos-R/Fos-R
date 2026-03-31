//! Configuration tab: toggles between visual mode and YAML editor.

use crate::config_editor::state::ConfigurationTabState;
use crate::config_editor::{host, host_validation, yaml_editor};
use crate::config_editor::toolbar::render_configuration_toolbar;
use crate::shared::config::file_ops::load_config_file_contents;
use crate::shared::config::model::Configuration;
use crate::shared::config::state::ConfigFileState;
use crate::shared::constants::colors::COLOR_ERROR;
use crate::shared::constants::ui::{SPACING_MD, TEXT_EDIT_DEFAULT_ROWS};
use crate::shared::widgets::helpers::{
    render_optional_text_area, render_optional_string_input, required_label,
};
use eframe::egui;

/// The main tab component
pub fn render_configuration_tab(
    ui: &mut egui::Ui,
    tab_state: &mut ConfigurationTabState,
    file_state: &mut ConfigFileState,
) {
    // Eagerly load config file contents when a file is selected
    load_config_file_contents(file_state);

    egui::ScrollArea::vertical().show(ui, |ui| {
        // File Selection
        render_configuration_toolbar(ui, tab_state, file_state);

        render_parse_error_banner(ui, file_state);

        if file_state.config_chosen {
            ui.separator();

            if !tab_state.is_code_mode {
                // Visual mode
                if let Some(model) = file_state.config_model.as_mut() {
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
                .config_model
                .as_ref()
                .is_some_and(host_validation::has_model_errors);
        }
    });
}

/// Sync model state to YAML content and update dirty flag.
///
/// Serializes the current model to YAML string and compares against
/// the clean snapshot to detect unsaved changes.
fn sync_model_to_yaml_state(state: &mut ConfigFileState) {
    let Some(model) = &state.config_model else {
        return;
    };

    // Serialize model to YAML (done once, reused for dirty check)
    let model_yaml = match serde_yaml::to_string(model) {
        Ok(yaml) => {
            state.config_error = None;
            yaml
        }
        Err(e) => {
            state.config_error = Some(e.to_string());
            return;
        }
    };
    state.config_file_content = Some(model_yaml.clone());

    // Update dirty flag by comparing with cached snapshot YAML
    if let Some(snap_yaml) = &state.clean_snapshot {
        state.is_dirty = model_yaml != *snap_yaml;
    }
}

/// Displays a YAML parse error banner below the toolbar, if any.
fn render_parse_error_banner(ui: &mut egui::Ui, state: &ConfigFileState) {
    if let Some(err) = &state.config_error {
        ui.separator();
        ui.colored_label(
            COLOR_ERROR,
            format!(
                "{} YAML parsing failed",
                egui_material_icons::icons::ICON_WARNING
            ),
        );
        ui.colored_label(COLOR_ERROR, err);
    }
}

/// Metadata rendering
fn render_metadata_section(ui: &mut egui::Ui, model: &mut Configuration) {
    ui.add_space(SPACING_MD);

    // Title
    ui.horizontal(|ui| {
        required_label(ui, "Title");
        let title = model.metadata.title.get_or_insert_with(String::new);
        ui.text_edit_singleline(title);
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
