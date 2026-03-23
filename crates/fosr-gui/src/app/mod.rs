//! Main Fos-R application: tab navigation, startup modal, and app state.

#[cfg(not(target_arch = "wasm32"))]
mod close_dialog;
mod startup_modal;
mod top_bar;

use crate::about_tab::show_about_tab_content;
use crate::config_editor::state::ConfigurationTabState;
use crate::config_editor::tab::show_configuration_tab_content;
use crate::run::state::RunTabState;
use crate::run::tab::show_run_tab_content;
use crate::shared::assets::{IMG_COMPUTER, IMG_INTERNET, IMG_LOGO, IMG_SERVER};
use crate::shared::config::state::ConfigurationFileState;
use crate::shared::constants::ui::{TOOLTIP_DELAY, ZOOM_DEFAULT, ZOOM_MAX, ZOOM_MIN};
#[cfg(not(target_arch = "wasm32"))]
use close_dialog::render_close_confirmation_dialog;
use eframe::egui;
use startup_modal::render_startup_modal;
use top_bar::{CurrentTab, TopBarState, render_top_bar};

#[derive(Default)]
pub struct FosrApp {
    current_tab: CurrentTab,
    style_initialized: bool,
    images_preloaded: bool,
    zoom_factor: f32,
    configuration_file_state: ConfigurationFileState,
    configuration_tab_state: ConfigurationTabState,
    run_tab_state: RunTabState,
    /// Whether to show the close confirmation dialog
    #[cfg(not(target_arch = "wasm32"))]
    show_close_confirmation: bool,
    /// Whether the user has confirmed they want to close
    #[cfg(not(target_arch = "wasm32"))]
    allowed_to_close: bool,
}

impl eframe::App for FosrApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Set default zoom once
        if !self.style_initialized {
            self.zoom_factor = ZOOM_DEFAULT;
            ctx.options_mut(|option| option.zoom_factor = self.zoom_factor);
            ctx.style_mut(|s| s.interaction.tooltip_delay = TOOLTIP_DELAY);

            // On web, use dark theme to match with the Fos-R website's theme
            #[cfg(target_arch = "wasm32")]
            ctx.set_theme(egui::Theme::Dark);

            self.style_initialized = true;
        }

        // Clamp zoom to min/max (prevents Ctrl+/- from exceeding limits)
        let current_zoom = ctx.zoom_factor();
        if current_zoom < ZOOM_MIN || current_zoom > ZOOM_MAX {
            let clamped_zoom = current_zoom.clamp(ZOOM_MIN, ZOOM_MAX);
            ctx.set_zoom_factor(clamped_zoom);
            self.zoom_factor = clamped_zoom;
        }

        // Set the image loaders
        // Required for egui to display images
        egui_extras::install_image_loaders(ctx);

        // Preload all images to avoid spinners/fallbacks on first visit
        if !self.images_preloaded {
            let _ = IMG_SERVER.load(ctx, Default::default(), Default::default());
            let _ = IMG_COMPUTER.load(ctx, Default::default(), Default::default());
            let _ = IMG_INTERNET.load(ctx, Default::default(), Default::default());
            let _ = IMG_LOGO.load(ctx, Default::default(), Default::default());
            self.images_preloaded = true;
        }

        // Handle close confirmation if there are active Wireshark sessions
        #[cfg(not(target_arch = "wasm32"))]
        {
            let has_active_sessions = self
                .run_tab_state
                .generation
                .temp_pcap_files
                .iter()
                .any(|(handle, _)| !handle.is_finished());

            if ctx.input(|i| i.viewport().close_requested()) {
                if self.allowed_to_close {
                    // Do nothing, let the app close
                } else if has_active_sessions {
                    ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                    self.show_close_confirmation = true;
                }
            }
        }

        // Startup modal: choose configuration source
        if !self.configuration_file_state.config_chosen {
            // Render empty CentralPanel for background, then modal on top
            egui::CentralPanel::default().show(ctx, |_ui| {});
            render_startup_modal(ctx, &mut self.configuration_file_state);
            return;
        }

        // Close confirmation dialog
        #[cfg(not(target_arch = "wasm32"))]
        render_close_confirmation_dialog(
            ctx,
            &mut self.show_close_confirmation,
            &mut self.allowed_to_close,
        );

        // Render top bar and get updated state
        let top_bar_state = TopBarState {
            current_tab: self.current_tab,
            zoom_factor: self.zoom_factor,
            has_errors: self.configuration_file_state.has_errors,
        };
        let updated_state = render_top_bar(ctx, top_bar_state);
        self.current_tab = updated_state.current_tab;
        self.zoom_factor = updated_state.zoom_factor;

        // The Central Panel is the region left after adding the Top, Bottom and Side panels.
        egui::CentralPanel::default().show(ctx, |ui| {
            // Display the tab content depending on the currently select tab
            // Note: Run tab doesn't use ScrollArea as it has its own layout
            match self.current_tab {
                CurrentTab::Run => {
                    show_run_tab_content(
                        ui,
                        &mut self.run_tab_state,
                        &mut self.configuration_file_state,
                    );
                }
                CurrentTab::Configuration => {
                    // Wrap in ScrollArea for vertical scrolling
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        show_configuration_tab_content(
                            ui,
                            &mut self.configuration_tab_state,
                            &mut self.configuration_file_state,
                        );
                    });
                }
                CurrentTab::About => {
                    // Wrap in ScrollArea for vertical scrolling
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        show_about_tab_content(ui);
                    });
                }
            }
        });
    }
}
