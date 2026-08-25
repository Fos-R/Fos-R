//! Predefined configuration templates: Home, Enterprise, Datacenter.

use crate::shared::config::state::ConfigFileState;
use fosr_lib::network::{Metadata, NetworkYaml};
use include_dir::Dir;
use include_dir::include_dir;

pub fn get_default_templates() -> Vec<NetworkYaml> {
    let d: Dir = include_dir!("$CARGO_MANIFEST_DIR/default_templates");
    d.files()
        .inspect(|e| {
            log::debug!("Loading default template {:?}", e.path());
        })
        .map(|f: &include_dir::File| {
            fosr_lib::network::reversibly_import_network(f.contents_utf8().unwrap())
        })
        .collect()
}

/// Load a template into the configuration file state.
///
/// Parses the template YAML first, then applies state changes only on success.
/// On parse failure, sets the error without modifying the existing model.
pub fn load_template(state: &mut ConfigFileState, template: &NetworkYaml) {
    // Normalize snapshot through serde_yaml so dirty comparison is consistent
    let snapshot = serde_yaml::to_string(&template).unwrap_or_default();

    // Apply state changes only after successful parse
    apply_template_to_state(state, template, snapshot);
}

/// Reset state and apply a successfully-parsed template.
fn apply_template_to_state(state: &mut ConfigFileState, model: &NetworkYaml, snapshot: String) {
    state.picked_config_file = None;
    state.config_file_content = Some(snapshot.clone());
    state.loaded_template_id = Some(model.metadata.title.clone());
    state.config_model = Some(model.clone());
    state.clean_snapshot = Some(snapshot);
    state.config_error = None;
    state.config_chosen = true;
    state.is_dirty = false;
}

/// Load an empty configuration with only metadata.
pub fn load_empty_config(state: &mut ConfigFileState) {
    let model = NetworkYaml {
        metadata: Metadata {
            title: "New network".to_string(),
            desc: None,
            author: None,
            date: None,
            version: None,
            format: None,
        },
        networks: vec![],
        internet: vec![],
    };
    let yaml = serde_yaml::to_string(&model).unwrap_or_default();
    state.picked_config_file = None;
    state.config_file_content = Some(yaml.clone());
    state.config_model = Some(model);
    state.clean_snapshot = Some(yaml);
    state.config_error = None;
    state.config_chosen = true;
    state.is_dirty = false;
    state.loaded_template_id = None;
}
