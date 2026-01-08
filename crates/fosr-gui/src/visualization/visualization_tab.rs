use eframe::egui;

/**
 * Represents the state of the visualization tab.
 */
pub struct VisualizationTabState {}

impl Default for VisualizationTabState {
    fn default() -> Self {
        Self {}
    }
}

pub fn show_visualization_tab_content(
    ui: &mut egui::Ui,
    _visualization_tab_state: &mut VisualizationTabState,
) {
    ui.heading("COMING SOON");
}
