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
use super::state::{NetworkEdge, NetworkNode, ScreenshotStateMachine, GraphViewState};
use crate::run::state::RunTabState;
use crate::shared::constants::ui::FIT_TO_SCREEN_PADDING;
use eframe::egui;

/// Render the graph view with overlays.
///
/// This function:
/// 1. Sets up the egui_graphs GraphView with custom shapes
/// 2. Handles window resize (triggers fit-to-screen)
/// 3. Disables force-directed layout (uses circle layout)
/// 4. Handles screenshot export state machine
/// 5. Renders UI overlays (buttons, stats, legends)
pub fn render_graph_view(ui: &mut egui::Ui, state: &mut RunTabState) {
    let inner_response = egui::CentralPanel::default().show(ui.ctx(), |ui| {
        handle_window_resize(ui, &mut state.visualization.view);

        let fit_to_screen = take_reset_request(&mut state.visualization.view);

        let mut graph_view = egui_graphs::GraphView::<
            NetworkNode,
            NetworkEdge,
            petgraph::Undirected,
            petgraph::stable_graph::DefaultIx,
            NetworkNodeShape,
            NetworkEdgeShape,
            egui_graphs::FruchtermanReingoldWithCenterGravityState,
            egui_graphs::LayoutForceDirected<egui_graphs::FruchtermanReingoldWithCenterGravity>,
        >::new(&mut state.visualization.network.graph)
            .with_interactions(&egui_graphs::SettingsInteraction::new()
                .with_node_clicking_enabled(true)
                .with_dragging_enabled(true))
            .with_event_sink(&state.visualization.modal.events_buffer)
            .with_styles(&egui_graphs::SettingsStyle::new().with_labels_always(true))
            .with_navigations(
                &egui_graphs::SettingsNavigation::new()
                    .with_fit_to_screen_enabled(fit_to_screen)
                    // padding to avoid cropping with labels and overlays
                    .with_fit_to_screen_padding(FIT_TO_SCREEN_PADDING)
                    .with_zoom_and_pan_enabled(true),
            );

        // TODO: handle layout properly instead of just deactivating auto-layout
        disable_force_directed_layout(ui, &mut state.visualization.view);

        ui.add(&mut graph_view);

        handle_screenshot_export(ui, &mut state.visualization);

        // Hide overlays during export to get clean screenshot
        if state.visualization.screenshot_export == ScreenshotStateMachine::Idle {
            render_overlay_buttons(ui, &mut state.visualization);
            render_overlay_stats(ui, &state.visualization);
            render_overlay_node_legend(ui);
            render_overlay_edge_legend(ui);
        }
    });

    // Use panel rect directly - it's already in screen coordinates
    // and represents the full panel area (ui.max_rect() excludes internal padding)
    state.visualization.view.graph_rect = Some(inner_response.response.rect);
}

/// Detect window resize and trigger fit-to-screen.
///
/// Compares current screen size with last known size.
/// On change, requests a reset to recalculate zoom/pan.
fn handle_window_resize(ui: &egui::Ui, view: &mut GraphViewState) {
    let screen_size = ui.ctx().content_rect().size();
    match view.last_screen_size {
        Some(last) if last != screen_size => {
            view.last_screen_size = Some(screen_size);
            view.reset_requested = true;
        }
        None => view.last_screen_size = Some(screen_size),
        _ => {}
    }
}

/// Consume reset request and return whether fit-to-screen should run.
///
/// Returns true for one frame when reset is requested,
/// then clears the flag so it doesn't repeat.
fn take_reset_request(view: &mut GraphViewState) -> bool {
    let fit = view.reset_requested;
    if fit {
        view.reset_requested = false;
    }
    fit
}

/// Disable force-directed layout to preserve circle layout.
///
/// Must be called once after the graph is first rendered.
/// The force-directed layout would override our circle layout.
fn disable_force_directed_layout(ui: &mut egui::Ui, view: &mut GraphViewState) {
    if view.layout_initialized {
        return;
    }
    let layout_state = egui_graphs::FruchtermanReingoldWithCenterGravityState {
        base: egui_graphs::FruchtermanReingoldState {
            is_running: false,
            ..Default::default()
        },
        extras: Default::default(),
    };
    egui_graphs::set_layout_state(ui, layout_state, None);
    view.layout_initialized = true;
}
