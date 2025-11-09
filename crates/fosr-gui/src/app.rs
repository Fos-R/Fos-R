use crate::ui::{
    GenerationState,
    show_about_tab_content,
    show_generation_tab_content,
};
#[cfg(not(target_arch = "wasm32"))]
use crate::ui::show_injection_tab_content;
use eframe::egui;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum CurrentTab {
    Generation,
    #[cfg(not(target_arch = "wasm32"))]
    Injection,
    About,
}

#[derive(Default)]
pub struct FosrApp {
    current_tab: CurrentTab,
    generation_state: GenerationState,
}

impl Default for CurrentTab {
    fn default() -> Self {
        CurrentTab::Generation
    }
}

impl eframe::App for FosrApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // The Top Panel is logically at the top of the window.
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            // Add a Menu Bar to host the tabs buttons
            egui::MenuBar::new().ui(ui, |ui| {
                if ui
                    .selectable_label(self.current_tab == CurrentTab::Generation, "Generation")
                    .clicked()
                {
                    self.current_tab = CurrentTab::Generation;
                }
                #[cfg(not(target_arch = "wasm32"))]
                if ui
                    .selectable_label(self.current_tab == CurrentTab::Injection, "Injection")
                    .clicked()
                {
                    self.current_tab = CurrentTab::Injection;
                }
                if ui
                    .selectable_label(self.current_tab == CurrentTab::About, "About")
                    .clicked()
                {
                    self.current_tab = CurrentTab::About;
                }
            });
        });

        // The Central Panel is the region left after adding the Top, Bottom and Side panels.
        egui::CentralPanel::default().show(ctx, |ui| {
            // Display the tab content depending on the currently select tab
            match self.current_tab {
                CurrentTab::Generation => {
                    show_generation_tab_content(ui, &mut self.generation_state);
                }
                #[cfg(not(target_arch = "wasm32"))]
                CurrentTab::Injection => {
                    show_injection_tab_content(ui);
                }
                CurrentTab::About => {
                    show_about_tab_content(ui);
                }
            }
        });
    }
}
