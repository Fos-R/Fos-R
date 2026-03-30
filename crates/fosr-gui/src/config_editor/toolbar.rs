//! Configuration toolbar UI: file picker, template menu, save button, and mode toggle.

use crate::config_editor::state::ConfigurationTabState;
use crate::config_templates::{load_template, TEMPLATES};
use crate::shared::config::file_ops::{enforce_metadata_defaults, trigger_file_import};
use crate::shared::config::state::ConfigFileState;
use crate::shared::constants::colors::COLOR_WARNING;
use crate::shared::constants::ui::SPACING_LG;
#[cfg(not(target_arch = "wasm32"))]
use crate::shared::file_io::save_file_desktop;
#[cfg(target_arch = "wasm32")]
use crate::shared::file_io::save_file_wasm;
use crate::shared::widgets::helpers::labeled_toggle;
use eframe::egui;

#[cfg(target_arch = "wasm32")]
use crate::shared::config::file_ops::poll_file_import;

/// Configuration toolbar UI.
///
/// Displays a file picker button, a template selection dropdown menu,
/// the selected file name and a Visual/Code mode toggle.
pub fn render_configuration_toolbar(
    ui: &mut egui::Ui,
    tab_state: &mut ConfigurationTabState,
    state: &mut ConfigFileState,
) {
    ui.horizontal(|ui| {
        ui.label("Configuration file:");
        render_file_import_button(ui, state);
        render_template_menu_button(ui, state);
        render_file_save_button(ui, state);
        render_filename(ui, state);
        render_mode_toggle_button(ui, tab_state);
    });
}

/// File import button with folder icon.
///
/// Opens a file picker dialog to select a configuration file.
/// On WASM, polls the async file picker result.
fn render_file_import_button(ui: &mut egui::Ui, state: &mut ConfigFileState) {
    if ui
        .button(egui_material_icons::icons::ICON_FOLDER_OPEN)
        .on_hover_text("Select a configuration file")
        .clicked()
    {
        trigger_file_import(state, ui.ctx());
    }

    #[cfg(target_arch = "wasm32")]
    poll_file_import(state);
}

/// Template menu button with document icon.
///
/// Dropdown menu listing available configuration templates.
/// Clicking a template loads it into the editor.
fn render_template_menu_button(ui: &mut egui::Ui, state: &mut ConfigFileState) {
    let template_menu =
        ui.menu_button(egui_material_icons::icons::ICON_DESCRIPTION, |menu_ui| {
            for template in TEMPLATES {
                if menu_ui
                    .button(format!("{} {}", template.icon, template.title))
                    .clicked()
                {
                    menu_ui.close();
                    load_template(state, template);
                }
            }
        });
    template_menu.response.on_hover_text("Open template");
}

/// Save button with "Save as" functionality.
///
/// Only visible when a configuration is loaded.
/// Serializes the config to YAML and triggers a file save dialog.
/// Updates metadata with current date before saving.
fn render_file_save_button(ui: &mut egui::Ui, state: &mut ConfigFileState) {
    if state.config_file_content.is_none() {
        return;
    }

    if ui
        .button(egui_material_icons::icons::ICON_SAVE_AS)
        .on_hover_text("Save as")
        .clicked()
    {
        if let Some(model) = state.config_model.as_mut() {
            enforce_metadata_defaults(model);
        }
        let content = match &state.config_model {
            Some(model) => serde_yaml::to_string(model).unwrap_or_default(),
            None => state.config_file_content.clone().unwrap_or_default(),
        };
        state.is_dirty = false;
        state.clean_snapshot = Some(content.clone());
        let default_name = state
            .picked_config_file
            .as_ref()
            .map(|f| f.file_name())
            .unwrap_or_else(|| "config.yaml".to_string());

        #[cfg(not(target_arch = "wasm32"))]
        {
            match save_file_desktop(content.as_bytes(), &default_name) {
                Ok(handle) => {
                    log::info!("Config saved to {}", handle.path().display());
                }
                Err(e) => {
                    log::error!("Failed to save config: {}", e);
                }
            }
        }

        #[cfg(target_arch = "wasm32")]
        {
            wasm_bindgen_futures::spawn_local(async move {
                match save_file_wasm(content.as_bytes(), &default_name).await {
                    Ok(_) => log::info!("Config saved"),
                    Err(e) => log::error!("Failed to save config: {}", e),
                }
            });
        }
    }
}

/// Filename display with dirty indicator.
///
/// Shows the selected file name or template name.
/// Displays a warning icon when there are unsaved changes.
/// On desktop, shows the full path on hover.
fn render_filename(ui: &mut egui::Ui, state: &ConfigFileState) {
    let filename = if let Some(file) = &state.picked_config_file {
        file.file_name()
    } else if let Some(template_id) = &state.loaded_template_id {
        format!("{}.yaml (built-in template)", template_id)
    } else {
        "No file selected".to_string()
    };

    #[cfg(not(target_arch = "wasm32"))]
    let hover_text = state
        .picked_config_file
        .as_ref()
        .map(|file| file.path().to_string_lossy().to_string())
        .unwrap_or_default();

    #[cfg(target_arch = "wasm32")]
    let hover_text = String::new();

    render_filename_with_status(ui, &filename, state.is_dirty, &hover_text);
}

/// Render filename label with optional dirty indicator and hover text.
fn render_filename_with_status(ui: &mut egui::Ui, filename: &str, is_dirty: bool, hover_text: &str) {
    if is_dirty {
        ui.colored_label(COLOR_WARNING, egui_material_icons::icons::ICON_WARNING)
            .on_hover_text("Unsaved changes detected — download the file to avoid losing them.");
        let label = ui.colored_label(COLOR_WARNING, filename);
        if !hover_text.is_empty() {
            label.on_hover_text(hover_text);
        }
    } else {
        let label = ui.label(filename);
        if !hover_text.is_empty() {
            label.on_hover_text(hover_text);
        }
    }
}

/// Mode toggle for switching between Visual and Code editing modes.
///
/// Positioned on the right side of the toolbar using RTL layout.
fn render_mode_toggle_button(ui: &mut egui::Ui, tab_state: &mut ConfigurationTabState) {
    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
        ui.add_space(SPACING_LG);
        // In RTL layout, rendering order is reversed,
        // so Code is passed first to appear visually on the right.
        labeled_toggle(
            ui,
            &mut tab_state.is_code_mode,
            &format!("{} Code", egui_material_icons::icons::ICON_CODE),
            &format!("{} Visual", egui_material_icons::icons::ICON_EDIT),
            "Code Mode: edit as raw YAML.",
            "Visual Mode: edit using the graphical interface.",
        );
    });
}
