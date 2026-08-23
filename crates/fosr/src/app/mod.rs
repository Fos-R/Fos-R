//! Main Fos-R application: tab navigation, startup modal, and app state.
//!
//! egui immediate mode: `update()` is called every frame,
//! you describe what to show, and state persists in the struct between frames.

#[cfg(not(target_arch = "wasm32"))]
mod close_dialog;
mod startup_modal;
mod top_bar;

use crate::about_tab::render_about_tab;
use crate::config_editor::state::ConfigurationTabState;
use crate::config_editor::tab::render_configuration_tab;
use crate::run::state::RunTabState;
use crate::run::tab::render_run_tab;
use crate::shared::assets::{IMG_COMPUTER, IMG_INTERNET, IMG_LOGO, IMG_SERVER};
use crate::shared::config::state::ConfigFileState;
use crate::shared::constants::ui::{TOOLTIP_DELAY, ZOOM_DEFAULT, ZOOM_MAX, ZOOM_MIN};
#[cfg(not(target_arch = "wasm32"))]
use close_dialog::render_close_confirmation_dialog;
use eframe::egui;
use startup_modal::render_startup_modal;
use top_bar::{AppTab, TopBarState, render_top_bar};

pub enum ViewState {
    Welcome,
    TemplateSelection,
    GraphTab,
    ConfigTab(ConfigTabSubstate),
    Exit,
}

pub enum ConfigTabSubstate {
    Visual,
    Code,
}

pub struct ViewOptions {
    zoom_factor: f32,


}

#[derive(Default)]
pub struct ExtraModals {
    #[cfg(not(target_arch = "wasm32"))]
    show_close_confirmation: bool,
    about: bool,
}

/// Main application state managing tabs, configuration, and PCAP generation.
/// // TODO: découpler la vue (machine à état) et le modèle
pub struct FosrApp {
    // View
    view_state: ViewState,
    extra_modals: ExtraModals,
    view_options: ViewOptions,
    // Model
    // current_tab: AppTab,
    // style_initialized: bool,
    // images_preloaded: bool,
    // zoom_factor: f32,
    config_file_state: ConfigFileState,
    configuration_tab_state: ConfigurationTabState,
    run_tab_state: RunTabState,
    // /// Whether to show the close confirmation dialog
    // /// Whether the user has confirmed they want to close
    // #[cfg(not(target_arch = "wasm32"))]
    // allowed_to_close: bool,
}

// TODO: ajouter un constructeur qui initialise tout ce qu’il faut

impl FosrApp {

    fn new(ctx: &egui::Context) -> Self {
        let app = FosrApp {
            view_state: ViewState::Welcome,
            view_options: ViewOptions { zoom_factor: ZOOM_DEFAULT },
            extra_modals: ExtraModals::default(),
            config_file_state: ConfigFileState::default(),
            configuration_tab_state: ConfigurationTabState::default(),
            run_tab_state: RunTabState::default(),
        };

        // Set default zoom once
        ctx.options_mut(|option| option.zoom_factor = app.view_options.zoom_factor);
        ctx.style_mut(|s| s.interaction.tooltip_delay = TOOLTIP_DELAY);

        // On web, use dark theme to match with the Fos-R website's theme
        #[cfg(target_arch = "wasm32")]
        ctx.set_theme(egui::Theme::Dark);

        // Preload all images to avoid spinners/fallbacks on first visit
        let _ = IMG_SERVER.load(ctx, Default::default(), Default::default());
        let _ = IMG_COMPUTER.load(ctx, Default::default(), Default::default());
        let _ = IMG_INTERNET.load(ctx, Default::default(), Default::default());
        let _ = IMG_LOGO.load(ctx, Default::default(), Default::default());

        app
    }

    /// Clamp zoom to min/max bounds (prevents Ctrl+/- from exceeding limits).
    fn clamp_zoom(&mut self, ctx: &egui::Context) {
        // Clamp zoom to min/max (prevents Ctrl+/- from exceeding limits)
        let current_zoom = ctx.zoom_factor();
        if !(ZOOM_MIN..=ZOOM_MAX).contains(&current_zoom) {
            let clamped_zoom = current_zoom.clamp(ZOOM_MIN, ZOOM_MAX);
            ctx.set_zoom_factor(clamped_zoom);
            self.view_options.zoom_factor = clamped_zoom;
        }
    }

    /// Check if any Wireshark sessions with temporary PCAP files are still running.
    #[cfg(not(target_arch = "wasm32"))]
    fn has_active_wireshark_sessions(&self) -> bool {
        self.run_tab_state
            .generation
            .temp_pcap_files
            .iter()
            .any(|(handle, _)| !handle.is_finished())
    }

    /// Handle close confirmation when there are active Wireshark sessions.
    #[cfg(not(target_arch = "wasm32"))]
    fn handle_close_confirmation(&mut self, ctx: &egui::Context) {
        if ctx.input(|i| i.viewport().close_requested()) {
            if self.allowed_to_close {
                // User confirmed: allow the app to close
            } else if self.has_active_wireshark_sessions() {
                // Active sessions: cancel close and show confirmation dialog
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                self.extra_modals.show_close_confirmation = true;
            }
        }
    }

    /// Render the top bar and update internal state from user interactions.
    fn render_top_bar(&mut self, ctx: &egui::Context) {
        let has_hosts = self
            .config_file_state
            .config_model
            .as_ref()
            .is_some_and(|m| m.count_hosts() > 0);

        // Render top bar and get updated state
        let top_bar_state = TopBarState {
            current_tab: self.current_tab,
            zoom_factor: self.zoom_factor,
            has_errors: self.config_file_state.has_errors,
            has_hosts,
        };
        let updated_state = render_top_bar(ctx, top_bar_state);

        // If Run tab is not accessible (only possible on initial load after choosing empty config),
        // force switch to Configuration to avoid rendering the graph with no hosts.
        if updated_state.current_tab == AppTab::Run
            && (!has_hosts || self.config_file_state.has_errors)
        {
            self.current_tab = AppTab::Configuration;
        } else {
            self.current_tab = updated_state.current_tab;
        }
        self.zoom_factor = updated_state.zoom_factor;
    }

    /// Render the current tab content in the central panel.
    fn render_current_tab(&mut self, ctx: &egui::Context) {
        // The Central Panel is the region left after adding the Top, Bottom and Side panels.
        egui::CentralPanel::default().show(ctx, |ui| {
            // Display the tab content depending on the currently select tab
            // Note: Run tab doesn't use ScrollArea as it has its own layout
            match self.current_tab {
                AppTab::Run => {
                    render_run_tab(ui, &mut self.run_tab_state, &mut self.config_file_state);
                }
                AppTab::Configuration => {
                    // Wrap in ScrollArea for vertical scrolling
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        render_configuration_tab(
                            ui,
                            &mut self.configuration_tab_state,
                            &mut self.config_file_state,
                        );
                    });
                }
                AppTab::About => {
                    // Wrap in ScrollArea for vertical scrolling
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        render_about_tab(ui);
                    });
                }
            }
        });
    }
}

impl eframe::App for FosrApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // One-time initialization
        self.init_style_once(ctx);
        self.clamp_zoom(ctx);

        // Set the image loaders
        // Required for egui to display images
        egui_extras::install_image_loaders(ctx);

        self.preload_images_once(ctx);

        // Handle close confirmation (native only)
        #[cfg(not(target_arch = "wasm32"))]
        self.handle_close_confirmation(ctx);

        // Startup modal: choose configuration source
        if !self.config_file_state.config_chosen {
            // Render empty CentralPanel for background, then modal on top
            egui::CentralPanel::default().show(ctx, |_ui| {});
            render_startup_modal(ctx, &mut self.config_file_state);
            return;
        }

        // Close confirmation dialog (native only)
        #[cfg(not(target_arch = "wasm32"))]
        render_close_confirmation_dialog(
            ctx,
            &mut self.show_close_confirmation,
            &mut self.allowed_to_close,
        );

        // Main UI
        self.render_top_bar(ctx);
        self.render_current_tab(ctx);
    }
}
