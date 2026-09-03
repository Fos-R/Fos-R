//! Combined state for the Run tab: visualization and generation with panel toggle.

use super::generation::state::GenerationState;
use super::graph::state::VisualizationState;
use eframe::egui;
use fosr_lib::models;
use std::sync::mpsc::{Receiver, TryRecvError, channel};

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
    // next_config: Option<fosr_lib::network::Network>,
    next_config: Receiver<fosr_lib::network::Network>,
}

impl RunTabState {
    pub fn check_config_update(&mut self) {
        if let Some(ref models) = self.models {
            if let Ok(network) = self.next_config.try_recv() {
                let mut bn = models.bn.write().unwrap();
                *bn = bn.with_network(&network).unwrap();
            }
        }
    }

    pub fn get_models(&mut self) -> Option<models::ArcModels> {
        if self.models.is_some() {
            // if let Some(config) = self.next_config.take() {
            //     self.update_config(&config);
            //     self.next_config = None;
            // }
            self.models.clone()
        } else {
            match self.models_receiver.try_recv() {
                Ok(models) => {
                    self.models = Some(models);
                    self.get_models()
                }
                Err(TryRecvError::Disconnected) => panic!("Error during models loading"),
                Err(TryRecvError::Empty) => None, // still waiting
            }
        }
    }
}

impl RunTabState {
    pub fn new(next_config: Receiver<fosr_lib::network::Network>, ctx: &egui::Context) -> Self {
        let (send, recv) = channel();
        let ctx = ctx.clone();
        let task = move || {
            let source = models::ModelsSource::CCD;
            send.send(
                models::Models::from_source_for_transfer_learning(&source)
                    .unwrap()
                    .into(),
            )
            .unwrap();
            ctx.request_repaint();
        };

        #[cfg(target_arch = "wasm32")]
        wasm_bindgen_futures::spawn_local(async move { task() });

        #[cfg(not(target_arch = "wasm32"))]
        std::thread::spawn(task);

        Self {
            models_receiver: recv,
            models: None,
            visualization: VisualizationState::default(),
            generation: GenerationState::default(),
            panel_open: true,
            next_config,
        }
    }
}
