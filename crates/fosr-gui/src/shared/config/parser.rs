//! Configuration YAML parsing.

use crate::shared::config::model::Configuration;
use crate::shared::config::state::ConfigurationFileState;

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
