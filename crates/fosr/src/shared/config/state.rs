//! Configuration file state management.

use fosr_lib::network::NetworkYaml;
use rfd::FileHandle;
#[cfg(target_arch = "wasm32")]
use std::sync::mpsc::Receiver;

/// State for the startup modal flow.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
pub enum StartupModalStep {
    #[default]
    Initial,
    TemplateSelection,
}

/// State for configuration file management including content, model, and UI state.
pub struct ConfigFileState {
    pub picked_config_file: Option<FileHandle>,
    #[cfg(target_arch = "wasm32")]
    pub config_file_receiver: Option<Receiver<Option<FileHandle>>>,
    pub config_file_content: Option<String>,
    #[cfg(target_arch = "wasm32")]
    pub config_file_content_receiver: Option<Receiver<Result<String, String>>>,
    pub config_model: Option<NetworkYaml>,
    pub config_error: Option<String>,
    /// Whether the user has chosen a configuration (default or imported).
    /// When false, the startup modal is shown.
    pub config_chosen: bool,
    pub is_dirty: bool,
    /// YAML snapshot of the clean state (for dirty detection).
    pub clean_snapshot: Option<String>,
    /// Whether the configuration has any errors (parse errors or validation errors).
    /// Updated by the configuration tab rendering each frame.
    pub has_errors: bool,
    /// Current state of the startup modal.
    pub modal_state: StartupModalStep,
    /// The ID of the currently loaded template, if any.
    pub loaded_template_id: Option<String>,
}

impl Default for ConfigFileState {
    fn default() -> Self {
        Self {
            picked_config_file: None,
            #[cfg(target_arch = "wasm32")]
            config_file_receiver: None,
            config_file_content: None,
            #[cfg(target_arch = "wasm32")]
            config_file_content_receiver: None,
            config_model: None,
            config_error: None,
            config_chosen: false,
            is_dirty: false,
            clean_snapshot: None,
            has_errors: false,
            modal_state: StartupModalStep::Initial,
            loaded_template_id: None,
        }
    }
}

impl ConfigFileState {
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
