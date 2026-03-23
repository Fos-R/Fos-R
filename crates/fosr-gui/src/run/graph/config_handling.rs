//! Configuration change detection and handling for visualization.
//!
//! This module monitors the configuration file state and triggers
//! visualization updates when the configuration changes.

use super::state::VisualizationState;
use crate::shared::config::state::ConfigurationFileState;
use crate::shared::ui_constants::DELAY_FRAMES_NORMAL;

/// Handle configuration file changes and update visualization state.
///
/// This function detects when the configuration has been removed, modified,
/// or replaced, and updates the visualization accordingly:
///
/// - If config is removed: stops visualization and resets to default state
/// - If config changes: parses new config and updates graph nodes/edges
/// - If parsing fails: logs error and resets to default state
pub fn handle_config_changes(
    state: &mut VisualizationState,
    configuration_file_state: &ConfigurationFileState,
) {
    // Check if config was removed or is empty
    let config_is_empty = configuration_file_state
        .config_file_content
        .as_ref()
        .map(|c| c.trim().is_empty())
        .unwrap_or(true);

    let was_config_removed =
        state.config_content.is_some() && configuration_file_state.config_file_content.is_none();

    // Only reset if we previously had a config (avoid resetting every frame when starting empty)
    let should_reset = was_config_removed || (config_is_empty && state.config_content.is_some());

    if should_reset {
        // Stop visualization if running, then reset to default
        if state.visualization_running {
            state.stop_visualization();
        }
        state.config_content = None;
        *state = VisualizationState::default();
        state.reset_view_requested = true;
        log::warn!("Config removed or empty, visualization reset to default");
        return;
    }

    // If config is empty and we have no config loaded, nothing to do
    if config_is_empty && state.config_content.is_none() {
        return;
    }

    // Check if config content has changed
    let needs_update = match (
        &state.config_content,
        &configuration_file_state.config_file_content,
    ) {
        (Some(current), Some(new)) => current != new,
        (None, Some(_)) => true,
        _ => false,
    };

    if needs_update {
        if let Some(config_content) = &configuration_file_state.config_file_content {
            // Stop visualization if running before updating config
            let was_running = state.visualization_running;
            if was_running {
                state.stop_visualization();
            }

            // Try to parse the config, handle errors gracefully
            // Use catch_unwind because import_config uses .expect() internally
            let config_result =
                std::panic::catch_unwind(|| fosr_lib::config::import_config(config_content));

            match config_result {
                Ok(config) => {
                    state.update_from_config(&config);
                    state.config_content = Some(config_content.clone());
                    // Only auto-restart if visualization was running before config change
                    if was_running {
                        state.auto_start_countdown = Some(DELAY_FRAMES_NORMAL);
                    }
                    state.reset_view_requested = true;
                }
                Err(e) => {
                    // Log the error once and reset to default state instead of crashing
                    // Store the config content so we don't retry parsing every frame
                    log::error!("Failed to parse configuration: {:?}", e);
                    *state = VisualizationState::default();
                    state.config_content = Some(config_content.clone());
                    state.reset_view_requested = true;
                }
            }
        }
    }
}
