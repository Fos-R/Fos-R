//! Run tab: live network visualization combined with PCAP generation controls.

use super::generation::bottom_panel::render_bottom_panel;
use super::generation::process::poll_generation_receivers;
use super::graph::config_handling::handle_config_changes;
use super::graph::flow_processing::{process_flow_events, update_active_links, update_graph_edges};
use super::graph::node_modal::{process_graph_events, render_node_info_modal};
use super::graph::view::render_graph_view;
use super::state::RunTabState;
use crate::run::graph::state::{GraphViewState, VisualizationState};
use crate::shared::config::file_ops::load_config_file_contents;
use crate::shared::config::state::ConfigFileState;
use eframe::egui;

/// Display the Run tab content.
///
/// Orchestrates visualization updates, event processing, and UI rendering.
pub fn render_run_tab(
    ui: &mut egui::Ui,
    state: &mut RunTabState,
    configuration_file_state: &mut ConfigFileState,
) {
    load_config_file_contents(configuration_file_state);
    handle_config_changes(&mut state.visualization, configuration_file_state);

    let models = state.get_models();
    handle_auto_start_visualization(&mut state.visualization, models);
    handle_delayed_fit_to_screen(&mut state.visualization.view);

    process_flow_events(&mut state.visualization);
    update_active_links(&mut state.visualization);
    update_graph_edges(&mut state.visualization);

    poll_generation_receivers(ui.ctx(), state);

    render_bottom_panel(ui.ctx(), state);

    render_graph_view(ui, state);
    process_graph_events(&mut state.visualization, configuration_file_state);

    render_node_info_modal(ui.ctx(), &mut state.visualization, configuration_file_state);
}

/// Handle auto-start visualization with a frame delay.
///
/// Waits for the countdown to reach zero before starting the visualization.
/// This allows the UI to render at least one frame before starting,
/// preventing visual glitches on initial load.
fn handle_auto_start_visualization(
    state: &mut VisualizationState,
    models: Option<fosr_lib::models::ArcModels>,
) {
    if let Some(countdown) = state.auto_start_countdown {
        if countdown > 0 {
            state.auto_start_countdown = Some(countdown - 1);
        } else if !state.flow.running
            && let Some(models) = models
        {
            let speed = state.flow.speed.clone();
            if let Err(e) = state.start_visualization(models, speed, true) {
                log::error!("Failed to auto-start visualization: {}", e);
            }
            state.auto_start_countdown = None;
        }
    }
}

/// Handle delayed fit-to-screen after view changes.
///
/// Waits for the countdown to reach zero before triggering a fit-to-screen.
/// Used after panel toggles or on initial load to ensure proper layout.
fn handle_delayed_fit_to_screen(view: &mut GraphViewState) {
    if let Some(countdown) = view.delayed_fit_countdown {
        if countdown > 0 {
            view.delayed_fit_countdown = Some(countdown - 1);
        } else {
            view.fit_to_screen_requested = true;
            view.delayed_fit_countdown = None;
        }
    }
}
