#[cfg(not(target_arch = "wasm32"))]
use crate::shared::file_io::{read_file_desktop, show_file_picker_desktop};
#[cfg(target_arch = "wasm32")]
use crate::shared::file_io::{read_file_wasm, show_file_picker_wasm};
use eframe::egui;
use rfd::FileHandle;
#[cfg(target_arch = "wasm32")]
use std::sync::mpsc::{Receiver, channel};

pub struct ConfigurationFileState {
    pub picked_config_file: Option<FileHandle>,
    #[cfg(target_arch = "wasm32")]
    pub config_file_receiver: Option<Receiver<Option<FileHandle>>>,
    pub config_file_content: Option<String>,
    #[cfg(target_arch = "wasm32")]
    pub config_file_content_receiver: Option<Receiver<Option<String>>>,
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
        }
    }
}

pub fn configuration_file_picker(
    ui: &mut egui::Ui,
    configuration_file_state: &mut ConfigurationFileState,
) {
    ui.horizontal(|ui| {
        ui.label("Configuration file:");

        // File Dialog to pick a config file
        if ui.button("Select file").clicked() {
            // Clear previous config content when selecting a new file
            configuration_file_state.config_file_content = None;
            #[cfg(target_arch = "wasm32")]
            {
                configuration_file_state.config_file_content_receiver = None;
            }

            #[cfg(not(target_arch = "wasm32"))]
            {
                // Only update if a file was actually selected
                let file = show_file_picker_desktop();
                if file.is_some() {
                    configuration_file_state.picked_config_file = file;
                }
            }

            #[cfg(target_arch = "wasm32")]
            {
                let (sender, receiver) = channel();
                configuration_file_state.config_file_receiver = Some(receiver);

                let ctx = ui.ctx().clone();
                wasm_bindgen_futures::spawn_local(async move {
                    let file = show_file_picker_wasm().await;
                    let _ = sender.send(file);
                    ctx.request_repaint();
                });
            }
        }

        #[cfg(target_arch = "wasm32")]
        // Check if we received a file from the async task
        {
            if let Some(receiver) = &configuration_file_state.config_file_receiver {
                if let Ok(file) = receiver.try_recv() {
                    // Only update if a file was actually selected
                    if file.is_some() {
                        configuration_file_state.picked_config_file = file;
                    }
                    configuration_file_state.config_file_receiver = None; // Dialog finished
                }
            }
        }

        // Display the filename of the picked file, or a placeholder
        let filename = configuration_file_state
            .picked_config_file
            .as_ref()
            .map(|file| file.file_name())
            .unwrap_or("No file selected".to_string());

        if configuration_file_state.picked_config_file.is_some() && ui.button("Remove").clicked() {
            configuration_file_state.picked_config_file = None;
            configuration_file_state.config_file_content = None;
        };

        // On desktop: filename with its full path on hover, on WASM: just the filename
        #[cfg(not(target_arch = "wasm32"))]
        {
            let path_text = configuration_file_state
                .picked_config_file
                .as_ref()
                .map(|file| file.path().to_string_lossy().to_string())
                .unwrap_or("Select a configuration file".to_string());
            ui.label(&filename).on_hover_text(path_text);
        }

        #[cfg(target_arch = "wasm32")]
        ui.label(&filename);
    });
}

pub fn load_config_file_contents(configuration_file_state: &mut ConfigurationFileState) {
    if let Some(file_handle) = &configuration_file_state.picked_config_file {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let content = read_file_desktop(file_handle);
            configuration_file_state.config_file_content = Some(content);
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
            }
        }
    }
}
