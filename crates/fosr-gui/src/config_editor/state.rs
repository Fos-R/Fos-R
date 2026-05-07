//! State for the configuration tab.

/// Represents the state of the configuration tab.
pub struct ConfigurationTabState {
    pub is_code_mode: bool,
}

impl Default for ConfigurationTabState {
    fn default() -> Self {
        Self {
            is_code_mode: false,
        }
    }
}
