//! Combined state for the Run tab: visualization and generation with panel toggle.

use super::generation::state::GenerationState;
use super::graph::state::VisualizationState;
use fosr_lib::models;
use std::sync::mpsc::{channel,Receiver,TryRecvError};
use std::thread;

/// State for the unified Run tab.
/// Combines visualization (live preview) and generation state.
pub struct RunTabState {
    pub visualization: VisualizationState,
    pub generation: GenerationState,
    /// Whether the side panel (generation options) is open
    pub panel_open: bool,
    models_receiver: Receiver<models::ArcModels>,
    models: Option<models::ArcModels>,
}

impl RunTabState {
    pub fn get_models(&mut self) -> Option<models::ArcModels> {
        if self.models.is_some() {
            self.models.clone()
        } else {
            match self.models_receiver.try_recv() {
                Ok(models) => {
                    self.models = Some(models);
                    self.models.clone()
                }
                Err(TryRecvError::Disconnected) =>
                    panic!("Error during models loading"),
                Err(TryRecvError::Empty) => None, // still waiting
            }
        }
    }
}

impl Default for RunTabState {
    fn default() -> Self {
        let (send, recv) = channel();
        // TODO wasm
        thread::spawn(move || {
            let source = models::ModelsSource::CCD;
            send.send(models::Models::from_source_for_transfer_learning(&source).unwrap().into()).unwrap();
        });

        Self {
            models_receiver: recv,
            models: None,
            visualization: VisualizationState::default(),
            generation: GenerationState::default(),
            panel_open: true,
        }
    }
}
