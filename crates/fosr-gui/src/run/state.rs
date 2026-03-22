//! Combined state for the Run tab: visualization and generation with panel toggle.

use crate::generation::state::GenerationState;
use crate::visualization::state::VisualizationState;

/// State for the unified Run tab.
/// Combines visualization (live preview) and generation state.
pub struct RunState {
    pub visualization: VisualizationState,
    pub generation: GenerationState,
    /// Whether the side panel (generation options) is open
    pub panel_open: bool,
}

impl Default for RunState {
    fn default() -> Self {
        Self {
            visualization: VisualizationState::default(),
            generation: GenerationState::default(),
            panel_open: true,
        }
    }
}
