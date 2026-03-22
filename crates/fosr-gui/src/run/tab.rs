//! Run tab: live network visualization combined with PCAP generation controls.

use super::bottom_panel::show_bottom_panel;
use super::config_handling::handle_config_changes;
use super::flow_processing::{process_flow_events, update_active_links, update_graph_edges};
use super::generation_process::poll_generation_receivers;
use super::graph_view::render_graph_view;
use super::state::RunState;
use crate::shared::configuration_file::{ConfigurationFileState, load_config_file_contents};
use crate::visualization::node_modal::{process_graph_events, render_node_info_modal};
use eframe::egui;

pub fn show_run_tab_content(
    ui: &mut egui::Ui,
    state: &mut RunState,
    configuration_file_state: &mut ConfigurationFileState,
) {
    // Load config file contents if a file is selected but content not yet loaded
    load_config_file_contents(configuration_file_state);

    // Handle config changes for visualization
    handle_config_changes(&mut state.visualization, configuration_file_state);

    // Auto-start visualization with delay (allows UI to render first)
    if let Some(countdown) = state.visualization.auto_start_countdown {
        if countdown > 0 {
            state.visualization.auto_start_countdown = Some(countdown - 1);
        } else if !state.visualization.visualization_running {
            let config = state.visualization.config_content.clone();
            let speed = state.visualization.speed.clone();
            if let Err(e) = state
                .visualization
                .start_visualization(config.as_deref(), speed, true)
            {
                log::error!("Failed to auto-start visualization: {}", e);
            }
            state.visualization.auto_start_countdown = None;
        }
    }

    // Handle delayed fit-to-screen (after panel toggle or on initial load)
    if let Some(countdown) = state.visualization.delayed_fit_countdown {
        if countdown > 0 {
            state.visualization.delayed_fit_countdown = Some(countdown - 1);
        } else {
            state.visualization.reset_view_requested = true;
            state.visualization.delayed_fit_countdown = None;
        }
    }

    // Process incoming flow events
    process_flow_events(&mut state.visualization);

    // Update active links (remove expired ones)
    update_active_links(&mut state.visualization);

    // Update graph edges based on active links
    update_graph_edges(&mut state.visualization);

    // Poll generation receivers (must be done before rendering UI)
    poll_generation_receivers(ui.ctx(), state);

    // Bottom panel (action bar + expandable options)
    show_bottom_panel(ui.ctx(), state, configuration_file_state);

    // Render the graph view
    render_graph_view(ui, state);

    // Process node click events and render info modal
    process_graph_events(&mut state.visualization, configuration_file_state);
    render_node_info_modal(ui.ctx(), &mut state.visualization, configuration_file_state);
}
