//! Configuration YAML parsing.

use crate::shared::config::state::ConfigFileState;
use fosr_lib::network::ConfigurationYaml;

/// Parse the YAML content into a ConfigurationYaml model.
/// Updates the state with the parsed model or an error message.
/// Handles change detection using a snapshot of the "clean" configuration.
pub fn parse_config_yaml(configuration_file_state: &mut ConfigFileState) {
    configuration_file_state.config_model = None;
    configuration_file_state.config_error = None;

    let Some(yaml) = configuration_file_state.config_file_content.as_deref() else {
        return;
    };

    match serde_yaml::from_str::<ConfigurationYaml>(yaml) {
        Ok(model) => {
            if configuration_file_state.clean_snapshot.is_none() {
                configuration_file_state.clean_snapshot =
                    Some(serde_yaml::to_string(&model).unwrap_or_default());
            }
            configuration_file_state.config_model = Some(model);
            configuration_file_state.is_dirty = true;
        }
        Err(e) => configuration_file_state.config_error = Some(e.to_string()),
    }
}
