use super::visualization_utils::distribute_nodes_circle;
use eframe::egui;
use egui_graphs::{
    FruchtermanReingoldWithCenterGravity, FruchtermanReingoldWithCenterGravityState,
    LayoutForceDirected,
};

/**
 * Represents the state of the visualization tab.
 */
pub struct VisualizationTabState {
    pub graph: egui_graphs::Graph<(), (), petgraph::Undirected>,
}

impl Default for VisualizationTabState {
    fn default() -> Self {
        let mut g = petgraph::stable_graph::StableGraph::default();
        let a = g.add_node(());
        let b = g.add_node(());
        let c = g.add_node(());

        g.add_edge(a, b, ());
        g.add_edge(b, c, ());
        g.add_edge(c, a, ());

        let mut graph = egui_graphs::Graph::<(), (), petgraph::Undirected>::from(&g);

        // Initially, the nodes are placed at position (0, 0) and need to be distributed
        distribute_nodes_circle(&mut graph);

        Self { graph }
    }
}

pub fn show_visualization_tab_content(
    ui: &mut egui::Ui,
    visualization_tab_state: &mut VisualizationTabState,
) {
    egui::CentralPanel::default().show(ui.ctx(), |ui| {
        ui.add(&mut egui_graphs::GraphView::<
            (),
            (),
            petgraph::Undirected,
            petgraph::stable_graph::DefaultIx,
            egui_graphs::DefaultNodeShape,
            egui_graphs::DefaultEdgeShape,
            FruchtermanReingoldWithCenterGravityState,
            LayoutForceDirected<FruchtermanReingoldWithCenterGravity>,
        >::new(&mut visualization_tab_state.graph));
    });
}
