use crate::generation::generation_state::GenerationTabState;
use crate::visualization::visualization_state::VisualizationTabState;

/// State for the unified Run tab.
/// Combines visualization (live preview) and generation state.
pub struct RunState {
    pub visualization: VisualizationTabState,
    pub generation: GenerationTabState,
    /// Whether the side panel (generation options) is open
    pub panel_open: bool,
}

impl Default for RunState {
    fn default() -> Self {
        Self {
            visualization: VisualizationTabState::default(),
            generation: GenerationTabState::default(),
            panel_open: true,
        }
    }
}
