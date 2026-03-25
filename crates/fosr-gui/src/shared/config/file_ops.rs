//! Configuration file operations: loading and saving config files.

use crate::shared::config::model::Configuration;
use crate::shared::config::parser::parse_config_yaml;
use crate::shared::config::state::ConfigurationFileState;
#[cfg(not(target_arch = "wasm32"))]
use crate::shared::file_io::{read_file_desktop, show_file_picker_desktop};
#[cfg(target_arch = "wasm32")]
use crate::shared::file_io::{read_file_wasm, show_file_picker_wasm};
use chrono::{DateTime, Local};
use eframe::egui;
#[cfg(target_arch = "wasm32")]
use std::sync::mpsc::channel;

/// Trigger a file import dialog to select a configuration file.
///
/// On desktop: synchronous file picker via native dialog.
/// On WASM: async file picker, result arrives via `config_file_receiver`.
/// Clears any previously loaded config state before picking a new file.
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
///
/// Should be called every frame in the UI to check for completed file picks.
/// When a file is picked, clears the loaded config and sets up for content loading.
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

/// Load the contents of the selected configuration file.
///
/// On desktop: reads file synchronously and parses YAML immediately.
/// On WASM: spawns async read, parses YAML when content arrives via channel.
///
/// Skips if content is already loaded to avoid re-reading every frame.
pub fn load_config_file_contents(configuration_file_state: &mut ConfigurationFileState) {
    // Already loaded — don't re-read from disk every frame
    if configuration_file_state.config_file_content.is_some() {
        return;
    }

    if let Some(file_handle) = &configuration_file_state.picked_config_file {
        #[cfg(not(target_arch = "wasm32"))]
        {
            match read_file_desktop(file_handle) {
                Ok(content) => {
                    configuration_file_state.config_file_content = Some(content);
                    parse_config_yaml(configuration_file_state);
                }
                Err(e) => {
                    configuration_file_state.config_error = Some(e);
                }
            }
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
                let result = read_file_wasm(&file_handle_clone).await;
                let _ = sender.send(result);
            });
        } else {
            if let Some(receiver) = &configuration_file_state.config_file_content_receiver {
                if let Ok(result) = receiver.try_recv() {
                    configuration_file_state.config_file_content_receiver = None;
                    match result {
                        Ok(content) => {
                            configuration_file_state.config_file_content = Some(content);
                            parse_config_yaml(configuration_file_state);
                        }
                        Err(e) => {
                            configuration_file_state.config_error = Some(e);
                        }
                    }
                }
            }
        }
    }
}

/// Clear all loaded config state to allow loading a new file.
fn clear_loaded_config(configuration_file_state: &mut ConfigurationFileState) {
    configuration_file_state.config_file_content = None;
    configuration_file_state.config_model = None;
    configuration_file_state.config_error = None;
    configuration_file_state.is_dirty = false;
    configuration_file_state.clean_snapshot = None;
    configuration_file_state.loaded_template_id = None;

    #[cfg(target_arch = "wasm32")]
    {
        configuration_file_state.config_file_content_receiver = None;
    }
}

/// Enforce date and format in metadata before saving.
///
/// Sets the date to today and format version to 1.
pub fn enforce_metadata_defaults(config: &mut Configuration) {
    let now: DateTime<Local> = Local::now();
    config.metadata.date = Some(now.format("%Y/%m/%d").to_string());
    config.metadata.format = Some(1);
}
