//! Predefined configuration templates: Home, Enterprise, Datacenter.

use fosr_lib::config::{ConfigurationYaml, Metadata};
use crate::shared::config::state::ConfigFileState;
use egui_material_icons::icons;

/// A predefined configuration template.
#[derive(Clone, Copy)]
pub struct Template {
    pub id: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub icon: &'static str,
    pub yaml: &'static str,
}

/// All available templates.
pub static TEMPLATES: &[Template] = &[
    Template {
        id: "home",
        title: "Home Network",
        description: "2-3 hosts, simple setup",
        icon: icons::ICON_HOME,
        yaml: include_str!("home.yaml"),
    },
    Template {
        id: "enterprise",
        title: "Enterprise",
        description: "DMZ + App + DB + Users",
        icon: icons::ICON_BUSINESS,
        yaml: include_str!("enterprise.yaml"),
    },
    Template {
        id: "datacenter",
        title: "Datacenter",
        description: "Many servers, no users",
        icon: icons::ICON_DNS,
        yaml: include_str!("datacenter.yaml"),
    },
];

/// Load a template into the configuration file state.
///
/// Parses the template YAML first, then applies state changes only on success.
/// On parse failure, sets the error without modifying the existing model.
pub fn load_template(state: &mut ConfigFileState, template: &Template) {
    // Parse first, fail-fast if invalid
    let model = match serde_yaml::from_str::<ConfigurationYaml>(template.yaml) {
        Ok(model) => model,
        Err(e) => {
            state.config_error = Some(e.to_string());
            return;
        }
    };

    // Apply state changes only after successful parse
    apply_template_to_state(state, template, model);
}

/// Reset state and apply a successfully-parsed template.
fn apply_template_to_state(
    state: &mut ConfigFileState,
    template: &Template,
    model: ConfigurationYaml,
) {
    state.picked_config_file = None;
    state.config_file_content = Some(template.yaml.to_string());
    state.config_model = Some(model);
    state.clean_snapshot = Some(template.yaml.to_string());
    state.config_error = None;
    state.config_chosen = true;
    state.is_dirty = false;
    state.loaded_template_id = Some(template.id.to_string());
}

/// Load an empty configuration with only metadata.
pub fn load_empty_config(state: &mut ConfigFileState) {
    let model = ConfigurationYaml {
        metadata: Metadata {
            title: String::new(),
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
