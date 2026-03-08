#[cfg(not(target_arch = "wasm32"))]
use crate::shared::file_io::{read_file_desktop, save_file_desktop, show_file_picker_desktop};
#[cfg(target_arch = "wasm32")]
use crate::shared::file_io::{read_file_wasm, save_file_wasm, show_file_picker_wasm};
use crate::{
    configuration::configuration_tab::ConfigurationTabState, shared::config_model::Configuration,
};
use chrono::{DateTime, Local};
use eframe::egui;
use rfd::FileHandle;
#[cfg(target_arch = "wasm32")]
use std::sync::mpsc::{Receiver, channel};

pub const DEFAULT_CONFIG_YAML: &str = include_str!("../default_config.yaml");

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
        }
    }
}

/// Load the built-in default configuration into the state.
pub fn load_default_config(state: &mut ConfigurationFileState) {
    state.picked_config_file = None;
    state.config_file_content = Some(DEFAULT_CONFIG_YAML.to_string());
    state.config_model = serde_yaml::from_str::<Configuration>(DEFAULT_CONFIG_YAML).ok();
    state.parse_error = None;
    state.config_chosen = true;
    state.is_dirty = false;
    state.clean_snapshot = state.config_model.clone();
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

        // Display the file name on disk, or indicate built-in default
        let filename = if let Some(file) = &configuration_file_state.picked_config_file {
            file.file_name()
        } else {
            "default_config.yaml (built-in)".to_string()
        };

        // Display Restore default button when a custom file is loaded
        if configuration_file_state.picked_config_file.is_some()
            && ui
                .button(egui_material_icons::icons::ICON_RESTORE)
                .on_hover_text("Restore default")
                .clicked()
        {
            configuration_file_state.picked_config_file = None;
            reset_loaded_config(configuration_file_state);
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
                    None => configuration_file_state.config_file_content.clone().unwrap_or_default(),
                };
                configuration_file_state.is_dirty = false;
                configuration_file_state.clean_snapshot = configuration_file_state.config_model.clone();
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
                ui.colored_label(egui::Color32::YELLOW, egui_material_icons::icons::ICON_WARNING)
                    .on_hover_text("Unsaved changes detected — download the file to avoid losing them.");
                ui.colored_label(egui::Color32::YELLOW, &filename)
                    .on_hover_text(path_text);
            } else {
                ui.label(&filename).on_hover_text(path_text);
            }
        }

        #[cfg(target_arch = "wasm32")]
        {
            if configuration_file_state.is_dirty {
                ui.colored_label(egui::Color32::YELLOW, egui_material_icons::icons::ICON_WARNING)
                    .on_hover_text("Unsaved changes detected — download the file to avoid losing them.");
                ui.colored_label(egui::Color32::YELLOW, &filename);
            } else {
                ui.label(&filename);
            }
        }

        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.add_space(8.0);
            ui.group(|ui| {
                ui.spacing_mut().item_spacing.x = 0.0;

                if ui
                    .selectable_label(
                        tab_state.is_code_mode,
                        egui_material_icons::icons::ICON_CODE,
                    )
                    .on_hover_text("Code Mode: edit the configuration directly as raw YAML.")
                    .clicked()
                {
                    tab_state.is_code_mode = true;
                }

                if ui
                    .selectable_label(
                        !tab_state.is_code_mode,
                        egui_material_icons::icons::ICON_EDIT,
                    )
                    .on_hover_text(
                        "Visual Mode: edit the configuration using the graphical interface. Fields and options are presented as forms instead of raw YAML.",
                    )
                    .clicked()
                {
                    tab_state.is_code_mode = false;
                }
            });
            ui.add_space(8.0);
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

    #[cfg(target_arch = "wasm32")]
    {
        configuration_file_state.config_file_content_receiver = None;
    }
}

/// Restore the built-in default configuration.
pub fn reset_loaded_config(configuration_file_state: &mut ConfigurationFileState) {
    load_default_config(configuration_file_state);

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
