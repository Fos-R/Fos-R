//! Configuration tab: toggles between visual mode and YAML editor.

use crate::config_editor::state::ConfigurationTabState;
use crate::config_editor::{host, host_validation, yaml_editor};
use crate::shared::colors::{COLOR_ERROR, COLOR_SUCCESS, COLOR_WARNING};
use crate::shared::config::file_ops::{configuration_file_picker, load_config_file_contents};
use crate::shared::config::model::Configuration;
use crate::shared::config::state::ConfigurationFileState;
use crate::shared::ui_constants::{SPACING_MD, TEXT_EDIT_DEFAULT_ROWS};
use crate::shared::ui_utils::{
    edit_optional_multiline_string, edit_optional_string, required_label,
};
use eframe::egui;

/// The main tab component
pub fn show_configuration_tab_content(
    ui: &mut egui::Ui,
    tab_state: &mut ConfigurationTabState,
    file_state: &mut ConfigurationFileState,
) {
    // Eagerly load config file contents when a file is selected
    load_config_file_contents(file_state);

    egui::ScrollArea::vertical().show(ui, |ui| {
        // File Selection
        configuration_file_picker(ui, tab_state, file_state);

        ui_parsing_status(ui, file_state);

        if file_state.config_chosen {
            ui.separator();

            if !tab_state.is_code_mode {
                // Visual mode
                if let Some(model) = file_state.config_model.as_mut() {
                    host::ui_hosts_section(ui, model);
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
                        ui_metadata(ui, model);
                    });
                }

                if let Some(model) = &file_state.config_model {
                    match serde_yaml::to_string(model) {
                        Ok(yaml) => {
                            file_state.config_file_content = Some(yaml);
                            file_state.parse_error = None;
                        }
                        Err(e) => {
                            file_state.parse_error = Some(e.to_string());
                        }
                    }

                    if let Some(snapshot) = &file_state.clean_snapshot {
                        let model_yaml = serde_yaml::to_string(model).unwrap_or_default();
                        let snap_yaml = serde_yaml::to_string(snapshot).unwrap_or_default();
                        file_state.is_dirty = model_yaml != snap_yaml;
                    }
                }
            } else {
                yaml_editor::ui_yaml_editor(ui, file_state);
            }

            // Update error flag (parse errors + host validation errors)
            file_state.has_errors = file_state.parse_error.is_some()
                || file_state
                    .config_model
                    .as_ref()
                    .is_some_and(host_validation::has_model_errors);
        }
    });
}

/// Status & Feedback
fn ui_parsing_status(ui: &mut egui::Ui, state: &ConfigurationFileState) {
    if state.picked_config_file.is_some() {
        if let Some(err) = &state.parse_error {
            ui.colored_label(COLOR_ERROR, "YAML parsing failed:");
            ui.label(err);
        } else if state.config_model.is_some() {
            ui.colored_label(COLOR_SUCCESS, "YAML parsed successfully");
        } else if state.config_file_content.is_some() {
            ui.colored_label(COLOR_WARNING, "YAML loaded, but not parsed yet.");
        }
        ui.separator();
    }
}

/// Metadata rendering
fn ui_metadata(ui: &mut egui::Ui, model: &mut Configuration) {
    ui.add_space(SPACING_MD);

    // Title
    ui.horizontal(|ui| {
        required_label(ui, "Title");
        let title = model.metadata.title.get_or_insert_with(String::new);
        ui.text_edit_singleline(title);
    });

    edit_optional_multiline_string(
        ui,
        "Description",
        &mut model.metadata.desc,
        "Optional description",
        TEXT_EDIT_DEFAULT_ROWS,
    );

    edit_optional_string(ui, "Author", &mut model.metadata.author, "Jane Doe");

    edit_optional_string(ui, "Version", &mut model.metadata.version, "0.1.0");
}
