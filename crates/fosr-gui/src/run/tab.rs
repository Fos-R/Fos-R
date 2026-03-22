//! Run tab: live network visualization combined with PCAP generation controls.

use super::bottom_panel::show_bottom_panel;
use super::config_handling::handle_config_changes;
use super::flow_processing::{process_flow_events, update_active_links, update_graph_edges};
use super::generation_process::poll_generation_receivers;
use super::state::RunState;
use crate::shared::configuration_file::{ConfigurationFileState, load_config_file_contents};
use crate::shared::ui_constants::FIT_TO_SCREEN_PADDING;
use crate::visualization::node_modal::{process_graph_events, render_node_info_modal};
use crate::visualization::overlays::{
    render_overlay_buttons, render_overlay_edge_legend, render_overlay_node_legend,
    render_overlay_stats,
};
use crate::visualization::screenshot::handle_screenshot_export;
use crate::visualization::shapes::{NetworkEdgeShape, NetworkNodeShape};
use crate::visualization::state::{EdgeData, ExportState, NodeData};
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

/// Render the graph view with overlays
fn render_graph_view(ui: &mut egui::Ui, state: &mut RunState) {
    let inner_response = egui::CentralPanel::default().show(ui.ctx(), |ui| {
        // Enable node clicking and dragging
        let interactions = egui_graphs::SettingsInteraction::new()
            .with_node_clicking_enabled(true)
            .with_dragging_enabled(true);

        // Reset view on window resize
        let screen_size = ui.ctx().content_rect().size();
        match state.visualization.last_screen_size {
            Some(last) if last != screen_size => {
                state.visualization.last_screen_size = Some(screen_size);
                state.visualization.reset_view_requested = true;
            }
            None => state.visualization.last_screen_size = Some(screen_size),
            _ => {}
        }

        // When reset is requested, enable fit-to-screen for one frame
        // so egui_graphs recalculates the proper zoom/pan to center the graph
        let fit_to_screen = state.visualization.reset_view_requested;
        if state.visualization.reset_view_requested {
            state.visualization.reset_view_requested = false;
        }

        let mut graph_view = egui_graphs::GraphView::<
            NodeData,
            EdgeData,
            petgraph::Undirected,
            petgraph::stable_graph::DefaultIx,
            NetworkNodeShape,
            NetworkEdgeShape,
            egui_graphs::FruchtermanReingoldWithCenterGravityState,
            egui_graphs::LayoutForceDirected<egui_graphs::FruchtermanReingoldWithCenterGravity>,
        >::new(&mut state.visualization.graph)
        .with_interactions(&interactions)
        .with_event_sink(&state.visualization.events_buffer)
        .with_styles(&egui_graphs::SettingsStyle::new().with_labels_always(true))
        .with_navigations(
            &egui_graphs::SettingsNavigation::new()
                .with_fit_to_screen_enabled(fit_to_screen)
                .with_fit_to_screen_padding(FIT_TO_SCREEN_PADDING) // padding to avoid cropping with labels and overlays
                .with_zoom_and_pan_enabled(true),
        );

        // Disable force-directed layout to preserve circle layout
        // TODO: handle this properly instead of just deactivating the auto-layout
        if !state.visualization.layout_initialized {
            let layout_state = egui_graphs::FruchtermanReingoldWithCenterGravityState {
                base: egui_graphs::FruchtermanReingoldState {
                    is_running: false,
                    ..Default::default()
                },
                extras: Default::default(),
            };
            egui_graphs::set_layout_state(ui, layout_state, None);
            state.visualization.layout_initialized = true;
        }

        ui.add(&mut graph_view);

        // Handle screenshot export state machine
        handle_screenshot_export(ui, &mut state.visualization);

        // Hide overlays during export to get clean screenshot
        if state.visualization.export_state != ExportState::Idle {
            return;
        }

        // Render overlays
        render_overlay_buttons(ui, &mut state.visualization);
        render_overlay_stats(ui, &state.visualization);
        render_overlay_node_legend(ui);
        render_overlay_edge_legend(ui);
    });

    // Use panel rect directly - it's already in screen coordinates
    // and represents the full panel area (ui.max_rect() excludes internal padding)
    let panel_rect = inner_response.response.rect;
    state.visualization.graph_rect = Some(panel_rect);
}
