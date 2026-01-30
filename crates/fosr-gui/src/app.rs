use crate::about_tab::show_about_tab_content;
use crate::configuration::configuration_tab::{
    ConfigurationTabState, show_configuration_tab_content,
};
use crate::generation::generation_tab::{GenerationTabState, show_generation_tab_content};
#[cfg(not(target_arch = "wasm32"))]
use crate::injection_tab::show_injection_tab_content;
use crate::shared::configuration_file::ConfigurationFileState;
use crate::visualization::visualization_tab::{
    VisualizationTabState, show_visualization_tab_content,
};
use eframe::egui;
#[cfg(not(target_arch = "wasm32"))]
use eframe::egui::global_theme_preference_switch;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum CurrentTab {
    Configuration,
    Visualization,
    Generation,
    #[cfg(not(target_arch = "wasm32"))]
    Injection,
    About,
}

impl Default for CurrentTab {
    fn default() -> Self {
        CurrentTab::Generation
    }
}

pub const DEFAULT_ZOOM: f32 = 1.4;

#[derive(Default)]
pub struct FosrApp {
    current_tab: CurrentTab,
    zoom_initialized: bool,
    configuration_file_state: ConfigurationFileState,
    configuration_tab_state: ConfigurationTabState,
    visualization_tab_state: VisualizationTabState,
    generation_tab_state: GenerationTabState,
}

impl eframe::App for FosrApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Set default zoom once
        if !self.zoom_initialized {
            ctx.options_mut(|option| option.zoom_factor = DEFAULT_ZOOM);
            self.zoom_initialized = true;
        }

        // Set the image loaders
        // Required for egui to display images
        egui_extras::install_image_loaders(ctx);

        // The Top Panel is logically at the top of the window.
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            // Add a Menu Bar to host the tabs buttons
            egui::MenuBar::new().ui(ui, |ui| {
                // On native, show the theme switch (using system theme by default)
                #[cfg(not(target_arch = "wasm32"))]
                global_theme_preference_switch(ui);
                // On web, use dark theme to match with the Fos-R website's theme
                #[cfg(target_arch = "wasm32")]
                ctx.set_theme(egui::Theme::Dark);

                if ui
                    .selectable_label(self.current_tab == CurrentTab::Generation, "Generation")
                    .clicked()
                {
                    self.current_tab = CurrentTab::Generation;
                }
                if ui
                    .selectable_label(
                        self.current_tab == CurrentTab::Configuration,
                        "Configuration",
                    )
                    .clicked()
                {
                    self.current_tab = CurrentTab::Configuration;
                }
                if ui
                    .selectable_label(
                        self.current_tab == CurrentTab::Visualization,
                        "Visualization",
                    )
                    .clicked()
                {
                    self.current_tab = CurrentTab::Visualization;
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
                    show_generation_tab_content(
                        ui,
                        &mut self.generation_tab_state,
                        &mut self.configuration_file_state,
                    );
                }
                CurrentTab::Configuration => {
                    show_configuration_tab_content(
                        ui,
                        &mut self.configuration_tab_state,
                        &mut self.configuration_file_state,
                    );
                }
                CurrentTab::Visualization => {
                    show_visualization_tab_content(
                        ui,
                        &mut self.visualization_tab_state,
                        &self.configuration_file_state,
                    );
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
