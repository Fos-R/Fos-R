//! Configuration file state management.

use fosr_lib::network::{Network, NetworkYaml};
use rfd::FileHandle;
#[cfg(target_arch = "wasm32")]
use std::sync::mpsc::Receiver;
use std::sync::mpsc::Sender;

/// State for configuration file management including content, model, and UI state.
pub struct ConfigFileState {
    pub picked_config_file: Option<FileHandle>,
    #[cfg(target_arch = "wasm32")]
    pub config_file_receiver: Option<Receiver<Option<FileHandle>>>,
    pub config_file_content: Option<String>,
    #[cfg(target_arch = "wasm32")]
    pub config_file_content_receiver: Option<Receiver<Result<String, String>>>,
    config_model: Option<NetworkYaml>,
    processed_config_model: Option<Network>,
    pub config_error: Option<String>,
    pub is_dirty: bool,
    /// YAML snapshot of the clean state (for dirty detection).
    pub clean_snapshot: Option<String>,
    /// Whether the configuration has any errors (parse errors or validation errors).
    /// Updated by the configuration tab rendering each frame.
    pub has_errors: bool,
    /// The ID of the currently loaded template, if any.
    pub loaded_template_id: Option<String>,
    next_config: Sender<fosr_lib::network::Network>,
}

impl ConfigFileState {
    pub fn get_processed_config_model(&self) -> &Option<Network> {
        &self.processed_config_model
    }

    pub fn get_config_model(&self) -> &Option<NetworkYaml> {
        &self.config_model
    }

    pub fn get_mut_config_model(&mut self) -> &mut Option<NetworkYaml> {
        &mut self.config_model
    }

    pub fn set_config_model(&mut self, network: NetworkYaml) {
        self.next_config.send(network.clone().into()).unwrap();
        self.processed_config_model = Some(network.clone().into());
        self.config_model = Some(network);
    }

    pub fn clear_config_model(&mut self) {
        //        self.next_config.send(network.clone().into()); // TODO: que faire ?
        self.config_model = None;
    }

    pub fn new(next_config: Sender<fosr_lib::network::Network>) -> Self {
        Self {
            picked_config_file: None,
            #[cfg(target_arch = "wasm32")]
            config_file_receiver: None,
            config_file_content: None,
            #[cfg(target_arch = "wasm32")]
            config_file_content_receiver: None,
            config_model: None,
            processed_config_model: None,
            config_error: None,
            is_dirty: false,
            clean_snapshot: None,
            has_errors: false,
            loaded_template_id: None,
            next_config,
        }
    }

    /// Serialize the current model to YAML and update `config_file_content`.
    pub fn sync_model_to_yaml(&mut self) {
        let Some(model) = &self.config_model else {
            return;
        };
        match serde_yaml::to_string(model) {
            Ok(yaml) => {
                self.config_error = None;
                self.config_file_content = Some(yaml);
            }
            Err(e) => {
                self.config_error = Some(e.to_string());
            }
        }
    }
}
