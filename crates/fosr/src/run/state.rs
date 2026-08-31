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
    // next_config is used when "update_config" is called before the model is ready
    // it is never used otherwise
    next_config: Option<fosr_lib::network::Network>,
}

impl RunTabState {
    pub fn update_config(&mut self, network: &fosr_lib::network::Network) {
        if let Some(ref models) = self.models {
            let mut bn = models.bn.write().unwrap();
            *bn = bn.with_network(network).unwrap();
        } else {
            self.next_config = Some(network.clone());
        }
    }

    pub fn get_models(&mut self) -> Option<models::ArcModels> {
        if let Some(ref models) = self.models {
            if let Some(config) = self.next_config.take() {
                self.update_config(&config);
                self.next_config = None;
            }
            self.models.clone()
        } else {
            match self.models_receiver.try_recv() {
                Ok(models) => {
                    self.models = Some(models);
                    self.get_models()
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
            next_config: None,
        }
    }
}
