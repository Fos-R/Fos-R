use eframe::egui;


/// Distributes the graph nodes in a circle layout.
/// Required for proper display on startup.
pub fn distribute_nodes_circle<N, E, Ty, Ix, Dn, De>(
    graph: &mut egui_graphs::Graph<N, E, Ty, Ix, Dn, De>,
) where
    N: Clone,
    E: Clone,
    Ty: petgraph::EdgeType,
    Ix: petgraph::graph::IndexType,
    Dn: egui_graphs::DisplayNode<N, E, Ty, Ix>,
    De: egui_graphs::DisplayEdge<N, E, Ty, Ix, Dn>,
{
    let n = graph.node_count().max(1) as f32;
    let radius = n.sqrt() * 80.0 + 100.0;

    let indices: Vec<_> = graph.g().node_indices().collect();
    for (i, idx) in indices.into_iter().enumerate() {
        if let Some(node) = graph.g_mut().node_weight_mut(idx) {
            let angle = (i as f32 / n) * std::f32::consts::TAU;
            node.set_location(egui::pos2(radius * angle.cos(), radius * angle.sin()));
        }
    }
}
