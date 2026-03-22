//! Graph view rendering for the Run tab.
//!
//! Renders the network visualization with custom node/edge shapes,
//! overlays, and screenshot export handling.

use super::overlays::{
    render_overlay_buttons, render_overlay_edge_legend, render_overlay_node_legend,
    render_overlay_stats,
};
use super::screenshot::handle_screenshot_export;
use super::shapes::{NetworkEdgeShape, NetworkNodeShape};
use super::state::{EdgeData, ExportState, NodeData};
use crate::run::state::RunState;
use crate::shared::ui_constants::FIT_TO_SCREEN_PADDING;
use eframe::egui;

/// Render the graph view with overlays.
///
/// This function:
/// 1. Sets up the egui_graphs GraphView with custom shapes
/// 2. Handles window resize (triggers fit-to-screen)
/// 3. Disables force-directed layout (uses circle layout)
/// 4. Handles screenshot export state machine
/// 5. Renders UI overlays (buttons, stats, legends)
pub fn render_graph_view(ui: &mut egui::Ui, state: &mut RunState) {
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
