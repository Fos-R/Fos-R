use eframe::egui;

pub fn distribute_nodes_circle(graph: &mut egui_graphs::Graph<(), (), petgraph::Undirected>) {
    let n = graph.node_count().max(1) as f32;
    let radius = n.sqrt() * 50.0 + 50.0;

    let indices: Vec<_> = graph.g().node_indices().collect();
    for (i, idx) in indices.into_iter().enumerate() {
        if let Some(node) = graph.g_mut().node_weight_mut(idx) {
            let angle = (i as f32 / n) * std::f32::consts::TAU;
            node.set_location(egui::pos2(radius * angle.cos(), radius * angle.sin()));
        }
    }
}
