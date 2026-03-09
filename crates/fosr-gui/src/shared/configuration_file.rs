#[cfg(not(target_arch = "wasm32"))]
use crate::shared::file_io::{read_file_desktop, save_file_desktop, show_file_picker_desktop};
#[cfg(target_arch = "wasm32")]
use crate::shared::file_io::{read_file_wasm, save_file_wasm, show_file_picker_wasm};
use crate::{
    configuration::configuration_tab::ConfigurationTabState,
    shared::config_model::Configuration,
    shared::ui_utils::labeled_toggle,
    templates::load_template_by_id,
};
use chrono::{DateTime, Local};
use eframe::egui;
use rfd::FileHandle;
#[cfg(target_arch = "wasm32")]
use std::sync::mpsc::{Receiver, channel};

/// State for the startup modal flow.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
pub enum StartupModalState {
    #[default]
    Initial,
    TemplateSelection,
}

/// Warning color (amber/orange).
const COLOR_WARNING: egui::Color32 = egui::Color32::from_rgb(230, 160, 0);

pub struct ConfigurationFileState {
    pub picked_config_file: Option<FileHandle>,
    #[cfg(target_arch = "wasm32")]
    pub config_file_receiver: Option<Receiver<Option<FileHandle>>>,
    pub config_file_content: Option<String>,
    #[cfg(target_arch = "wasm32")]
    pub config_file_content_receiver: Option<Receiver<Option<String>>>,
    pub config_model: Option<Configuration>,
    pub parse_error: Option<String>,
    /// Whether the user has chosen a configuration (default or imported).
    /// When false, the startup modal is shown.
    pub config_chosen: bool,
    pub is_dirty: bool,
    pub clean_snapshot: Option<Configuration>,
    /// Whether the configuration has any errors (parse errors or validation errors).
    /// Updated by the configuration tab rendering each frame.
    pub has_errors: bool,
    /// Current state of the startup modal.
    pub modal_state: StartupModalState,
    /// The ID of the currently loaded template, if any.
    pub loaded_template_id: Option<String>,
}

impl Default for ConfigurationFileState {
    fn default() -> Self {
        Self {
            picked_config_file: None,
            #[cfg(target_arch = "wasm32")]
            config_file_receiver: None,
            config_file_content: None,
            #[cfg(target_arch = "wasm32")]
            config_file_content_receiver: None,
            config_model: None,
            parse_error: None,
            config_chosen: false,
            is_dirty: false,
            clean_snapshot: None,
            has_errors: false,
            modal_state: StartupModalState::Initial,
            loaded_template_id: None,
        }
    }
}

/// Trigger a file import dialog (works on both desktop and WASM).
/// On desktop this is synchronous; on WASM the result arrives via `config_file_receiver`.
pub fn trigger_file_import(state: &mut ConfigurationFileState, ctx: &egui::Context) {
    state.config_file_content = None;
    #[cfg(target_arch = "wasm32")]
    {
        state.config_file_content_receiver = None;
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = ctx;
        let file = show_file_picker_desktop();
        if file.is_some() {
            state.picked_config_file = file;
            state.config_chosen = true;
            clear_loaded_config(state);
        }
    }

    #[cfg(target_arch = "wasm32")]
    {
        let (sender, receiver) = channel();
        state.config_file_receiver = Some(receiver);
        let ctx = ctx.clone();
        wasm_bindgen_futures::spawn_local(async move {
            let file = show_file_picker_wasm().await;
            let _ = sender.send(file);
            ctx.request_repaint();
        });
    }
}

/// Poll the WASM async file picker and apply the result if ready.
#[cfg(target_arch = "wasm32")]
pub fn poll_file_import(state: &mut ConfigurationFileState) {
    if let Some(receiver) = &state.config_file_receiver {
        if let Ok(file) = receiver.try_recv() {
            if file.is_some() {
                state.picked_config_file = file;
                state.config_chosen = true;
                clear_loaded_config(state);
            }
            state.config_file_receiver = None;
        }
    }
}

pub fn configuration_file_picker(
    ui: &mut egui::Ui,
    tab_state: &mut ConfigurationTabState,
    configuration_file_state: &mut ConfigurationFileState,
) {
    ui.horizontal(|ui| {
        ui.label("Configuration file:");

        if ui
            .button(egui_material_icons::icons::ICON_FOLDER_OPEN)
            .on_hover_text("Select a configuration file")
            .clicked()
        {
            trigger_file_import(configuration_file_state, ui.ctx());
        }

        #[cfg(target_arch = "wasm32")]
        poll_file_import(configuration_file_state);

        // Template dropdown menu (always visible)
        let template_menu = ui.menu_button(egui_material_icons::icons::ICON_DESCRIPTION, |menu_ui| {
            for template in crate::templates::all_templates() {
                if menu_ui
                    .button(format!("{} {}", template.icon, template.title))
                    .clicked()
                {
                    menu_ui.close();
                    load_template_by_id(configuration_file_state, template.id);
                }
            }
        });
        template_menu.response.on_hover_text("Open template");

        // Display the file name on disk, or indicate built-in template
        let filename = if let Some(file) = &configuration_file_state.picked_config_file {
            file.file_name()
        } else if let Some(template_id) = &configuration_file_state.loaded_template_id {
            format!("{}.yaml (built-in)", template_id)
        } else {
            "No file selected".to_string()
        };

        // Save as button (only when config content is available)
        if configuration_file_state.config_file_content.is_some() {
            if ui
                .button(egui_material_icons::icons::ICON_SAVE_AS)
                .on_hover_text("Save as")
                .clicked()
            {
                if let Some(model) = configuration_file_state.config_model.as_mut() {
                    enforce_metadata_defaults(model);
                }
                let content = match &configuration_file_state.config_model {
                    Some(model) => serde_yaml::to_string(model).unwrap_or_default(),
                    None => configuration_file_state
                        .config_file_content
                        .clone()
                        .unwrap_or_default(),
                };
                configuration_file_state.is_dirty = false;
                configuration_file_state.clean_snapshot =
                    configuration_file_state.config_model.clone();
                let default_name = configuration_file_state
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

        // On desktop: filename with its full path on hover, on WASM: just the filename
        #[cfg(not(target_arch = "wasm32"))]
        {
            let path_text = configuration_file_state
                .picked_config_file
                .as_ref()
                .map(|file| file.path().to_string_lossy().to_string())
                .unwrap_or("Default config selected".to_string());

            if configuration_file_state.is_dirty {
                ui.colored_label(COLOR_WARNING, egui_material_icons::icons::ICON_WARNING)
                    .on_hover_text(
                        "Unsaved changes detected — download the file to avoid losing them.",
                    );
                ui.colored_label(COLOR_WARNING, &filename)
                    .on_hover_text(path_text);
            } else {
                ui.label(&filename).on_hover_text(path_text);
            }
        }

        #[cfg(target_arch = "wasm32")]
        {
            if configuration_file_state.is_dirty {
                ui.colored_label(COLOR_WARNING, egui_material_icons::icons::ICON_WARNING)
                    .on_hover_text(
                        "Unsaved changes detected — download the file to avoid losing them.",
                    );
                ui.colored_label(COLOR_WARNING, &filename);
            } else {
                ui.label(&filename);
            }
        }

        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.add_space(8.0);
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
    });
}

pub fn load_config_file_contents(configuration_file_state: &mut ConfigurationFileState) {
    // Already loaded — don't re-read from disk every frame
    if configuration_file_state.config_file_content.is_some() {
        return;
    }

    if let Some(file_handle) = &configuration_file_state.picked_config_file {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let content = read_file_desktop(file_handle);
            configuration_file_state.config_file_content = Some(content);
            parse_config_yaml(configuration_file_state);
        }

        #[cfg(target_arch = "wasm32")]
        if configuration_file_state
            .config_file_content_receiver
            .is_none()
        {
            let (sender, receiver) = channel();
            configuration_file_state.config_file_content_receiver = Some(receiver);
            let file_handle_clone = file_handle.clone();

            wasm_bindgen_futures::spawn_local(async move {
                let content = read_file_wasm(&file_handle_clone).await;
                let _ = sender.send(Some(content));
            });
        } else {
            if let Some(receiver) = &configuration_file_state.config_file_content_receiver {
                if let Ok(content) = receiver.try_recv() {
                    configuration_file_state.config_file_content = content;
                    configuration_file_state.config_file_content_receiver = None;
                }
                if configuration_file_state.config_file_content.is_some() {
                    parse_config_yaml(configuration_file_state);
                }
            }
        }
    }
}

pub fn parse_config_yaml(configuration_file_state: &mut ConfigurationFileState) {
    configuration_file_state.config_model = None;
    configuration_file_state.parse_error = None;

    let Some(yaml) = configuration_file_state.config_file_content.as_deref() else {
        return;
    };

    match serde_yaml::from_str::<Configuration>(yaml) {
        Ok(model) => {
            if configuration_file_state.clean_snapshot.is_none() {
                configuration_file_state.clean_snapshot = Some(model.clone());
            }
            configuration_file_state.config_model = Some(model);
            configuration_file_state.is_dirty = true;
        }
        Err(e) => configuration_file_state.parse_error = Some(e.to_string()),
    }
}

/// Clear all loaded config state to allow loading a new file.
fn clear_loaded_config(configuration_file_state: &mut ConfigurationFileState) {
    configuration_file_state.config_file_content = None;
    configuration_file_state.config_model = None;
    configuration_file_state.parse_error = None;
    configuration_file_state.is_dirty = false;
    configuration_file_state.clean_snapshot = None;
    configuration_file_state.loaded_template_id = None;

    #[cfg(target_arch = "wasm32")]
    {
        configuration_file_state.config_file_content_receiver = None;
    }
}

/// Enforce date and format in metadata
fn enforce_metadata_defaults(config: &mut Configuration) {
    let now: DateTime<Local> = Local::now();

    config.metadata.date = Some(now.format("%Y/%m/%d").to_string());
    config.metadata.format = Some(1);
}
