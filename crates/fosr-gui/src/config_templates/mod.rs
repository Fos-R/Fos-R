//! Predefined configuration templates: Home, Enterprise, Datacenter.

use crate::shared::config::model::Configuration;
use crate::shared::config::state::ConfigurationFileState;
use egui_material_icons::icons;

/// A predefined configuration template.
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

/// Load a template by its ID into the configuration file state.
pub fn load_template_by_id(state: &mut ConfigurationFileState, id: &str) {
    if let Some(template) = TEMPLATES.iter().find(|t| t.id == id) {
        load_template(state, template);
    }
}

/// Load a template into the configuration file state.
fn load_template(state: &mut ConfigurationFileState, template: &Template) {
    state.picked_config_file = None;
    state.config_file_content = Some(template.yaml.to_string());
    state.config_model = None;
    state.parse_error = None;

    match serde_yaml::from_str::<Configuration>(template.yaml) {
        Ok(model) => {
            state.config_model = Some(model);
            state.clean_snapshot = state.config_model.clone();
            state.config_chosen = true;
            state.is_dirty = false;
            state.loaded_template_id = Some(template.id.to_string());
        }
        Err(e) => {
            state.parse_error = Some(e.to_string());
        }
    }
}

/// Get all available templates.
pub fn all_templates() -> &'static [Template] {
    TEMPLATES
}
