//! Graph layout: circular node distribution for initial display.

use crate::shared::constants::ui::{GRAPH_LAYOUT_RADIUS_BASE, GRAPH_LAYOUT_RADIUS_MULTIPLIER};
use eframe::egui;

/// Distributes the graph nodes in a circle layout.
/// Required for proper display on startup.
pub fn arrange_nodes_in_circle<N, E, Ty, Ix, Dn, De>(
    graph: &mut egui_graphs::Graph<N, E, Ty, Ix, Dn, De>,
) where
    N: Clone,
    E: Clone,
    Ty: petgraph::EdgeType,
    Ix: petgraph::graph::IndexType,
    Dn: egui_graphs::DisplayNode<N, E, Ty, Ix>,
    De: egui_graphs::DisplayEdge<N, E, Ty, Ix, Dn>,
{
    let node_count = graph.node_count().max(1) as f32;
    let radius = node_count.sqrt() * GRAPH_LAYOUT_RADIUS_MULTIPLIER + GRAPH_LAYOUT_RADIUS_BASE;

    let indices: Vec<_> = graph.g().node_indices().collect();
    for (i, idx) in indices.into_iter().enumerate() {
        if let Some(node) = graph.g_mut().node_weight_mut(idx) {
            let angle = (i as f32 / node_count) * std::f32::consts::TAU;
            node.set_location(egui::pos2(radius * angle.cos(), radius * angle.sin()));
        }
    }
}
