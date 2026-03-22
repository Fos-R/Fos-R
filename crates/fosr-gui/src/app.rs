//! Main Fos-R application: tab navigation, startup modal, and app state.

use crate::about_tab::show_about_tab_content;
use crate::config_templates::{all_templates, load_template_by_id};
use crate::configuration::tab::{ConfigurationTabState, show_configuration_tab_content};
use crate::run::{RunState, show_run_tab_content};
use crate::shared::colors::{COLOR_ERROR, COLOR_TEXT_MUTED};
#[cfg(target_arch = "wasm32")]
use crate::shared::configuration_file::poll_file_import;
use crate::shared::configuration_file::{
    ConfigurationFileState, StartupModalState, trigger_file_import,
};
#[cfg(not(target_arch = "wasm32"))]
use crate::shared::ui_constants::MODAL_WIDTH_SM;
use crate::shared::ui_constants::{
    BUTTON_PADDING, ICON_SIZE_LG, MODAL_WIDTH_MD, PANEL_INNER_MARGIN, SPACING_LG, SPACING_SM,
    SPACING_XL, SPACING_XS, STARTUP_CARD_HEIGHT, STARTUP_COLUMNS_INITIAL,
    STARTUP_COLUMNS_TEMPLATES, TEXT_SIZE_DEFAULT, TEXT_SIZE_LG, TEXT_SIZE_SM, TOOLTIP_DELAY,
    ZOOM_DEFAULT, ZOOM_MAX, ZOOM_MIN, ZOOM_STEP,
};
use eframe::egui;
use eframe::egui::global_theme_preference_switch;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum CurrentTab {
    Configuration,
    Run,
    About,
}

impl Default for CurrentTab {
    fn default() -> Self {
        CurrentTab::Run
    }
}

#[derive(Default)]
pub struct FosrApp {
    current_tab: CurrentTab,
    style_initialized: bool,
    images_preloaded: bool,
    zoom_factor: f32,
    configuration_file_state: ConfigurationFileState,
    configuration_tab_state: ConfigurationTabState,
    run_state: RunState,
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
            let _ = egui::include_image!("../assets/server.png").load(
                ctx,
                Default::default(),
                Default::default(),
            );
            let _ = egui::include_image!("../assets/computer.png").load(
                ctx,
                Default::default(),
                Default::default(),
            );
            let _ = egui::include_image!("../assets/internet.png").load(
                ctx,
                Default::default(),
                Default::default(),
            );
            let _ = egui::include_image!("../../../public/logo.png").load(
                ctx,
                Default::default(),
                Default::default(),
            );
            self.images_preloaded = true;
        }

        // Handle close confirmation if there are active Wireshark sessions
        #[cfg(not(target_arch = "wasm32"))]
        {
            let has_active_sessions = self
                .run_state
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
        if self.show_close_confirmation {
            egui::Modal::new(egui::Id::new("close_confirmation_modal")).show(ctx, |ui| {
                ui.set_width(MODAL_WIDTH_SM);
                ui.heading("Confirm Exit");
                ui.add_space(SPACING_LG);
                ui.label("You have Wireshark session(s) open with temporary PCAP files.");
                ui.label("Closing will delete these files.");
                ui.add_space(SPACING_XL);
                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() {
                        self.show_close_confirmation = false;
                    }
                    if ui.button("Exit").clicked() {
                        self.show_close_confirmation = false;
                        self.allowed_to_close = true;
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
            });
        }

        // The Top Panel is logically at the top of the window.
        egui::TopBottomPanel::top("top_panel")
            .frame(egui::Frame::side_top_panel(&ctx.style()).inner_margin(egui::Margin::symmetric(PANEL_INNER_MARGIN.0, PANEL_INNER_MARGIN.1)))
            .show(ctx, |ui| {
                // Add a Menu Bar to host the tabs buttons
                egui::MenuBar::new().ui(ui, |ui| {
                    ui.spacing_mut().button_padding = egui::vec2(BUTTON_PADDING.0, BUTTON_PADDING.1);
                    let tab_text_size = TEXT_SIZE_DEFAULT;

                    let has_errors = self.configuration_file_state.has_errors;

                    // Run tab (combines Live Preview + Generation)
                    let run_button = egui::Button::new(
                        egui::RichText::new("Run").size(tab_text_size),
                    )
                        .selected(self.current_tab == CurrentTab::Run);

                    let response = ui.add_enabled(!has_errors, run_button);

                    let response = if has_errors {
                        response.on_disabled_hover_text("Configuration is invalid. Fix errors in the Configuration tab to enable Run.")
                    } else {
                        response.on_hover_text("Live preview and PCAP generation from the current configuration.")
                    };

                    if !has_errors && response.clicked() {
                        self.current_tab = CurrentTab::Run;
                    }

                    // Configuration tab
                    let label_text = if self.configuration_file_state.has_errors {
                        egui::RichText::new("⚠ Configuration").color(COLOR_ERROR).size(tab_text_size)
                    } else {
                        egui::RichText::new("Configuration").size(tab_text_size)
                    };
                    if ui
                        .add(egui::Button::new(label_text)
                            .selected(self.current_tab == CurrentTab::Configuration))
                        .on_hover_text("Edit the network configuration: hosts, interfaces, and services.")
                        .clicked()
                    {
                        self.current_tab = CurrentTab::Configuration;
                    };

                    // About tab
                    if ui
                        .add(egui::Button::new(
                            egui::RichText::new("About").size(tab_text_size),
                        ).selected(self.current_tab == CurrentTab::About))
                        .on_hover_text("About Fos-R and its authors.")
                        .clicked()
                    {
                        self.current_tab = CurrentTab::About;
                    }

                    // Right-align utility buttons so they sit on the opposite side of the tabs
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        // On web, show a fullscreen toggle button
                        #[cfg(target_arch = "wasm32")]
                        {
                            let is_fullscreen = web_sys::window()
                                .and_then(|w| w.document())
                                .and_then(|d| d.fullscreen_element())
                                .is_some();

                            let (icon, tooltip) = if is_fullscreen {
                                (egui_material_icons::icons::ICON_FULLSCREEN_EXIT, "Exit fullscreen")
                            } else {
                                (egui_material_icons::icons::ICON_FULLSCREEN, "Fullscreen")
                            };

                            if ui.button(icon).on_hover_text(tooltip).clicked() {
                                if let Some(window) = web_sys::window() {
                                    if let Some(document) = window.document() {
                                        if is_fullscreen {
                                            document.exit_fullscreen();
                                        } else if let Some(canvas) = document.get_element_by_id("fosr_gui_canvas") {
                                            let _ = canvas.request_fullscreen();
                                        }
                                    }
                                }
                            }
                        }

                        #[cfg(not(target_arch = "wasm32"))]
                        ui.add_space(SPACING_SM);

                        // Show the theme switch
                        global_theme_preference_switch(ui);

                        // Zoom controls
                        if ui
                            .button(egui_material_icons::icons::ICON_ADD)
                            .on_hover_text("Zoom in")
                            .clicked()
                        {
                            let current_zoom = ctx.zoom_factor();
                            let new_zoom = (current_zoom + ZOOM_STEP).min(ZOOM_MAX);
                            ctx.set_zoom_factor(new_zoom);
                            self.zoom_factor = new_zoom;
                        }
                        ui.label(format!("{:.0}%", ctx.zoom_factor() * 100.0));
                        if ui
                            .button(egui_material_icons::icons::ICON_REMOVE)
                            .on_hover_text("Zoom out")
                            .clicked()
                        {
                            let current_zoom = ctx.zoom_factor();
                            let new_zoom = (current_zoom - ZOOM_STEP).max(ZOOM_MIN);
                            ctx.set_zoom_factor(new_zoom);
                            self.zoom_factor = new_zoom;
                        }
                    });
                });
            });

        // The Central Panel is the region left after adding the Top, Bottom and Side panels.
        egui::CentralPanel::default().show(ctx, |ui| {
            // Display the tab content depending on the currently select tab
            // Note: Run tab doesn't use ScrollArea as it has its own layout
            match self.current_tab {
                CurrentTab::Run => {
                    show_run_tab_content(
                        ui,
                        &mut self.run_state,
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

/// A clickable card with icon, title and description. Returns true if clicked.
fn startup_card(ui: &mut egui::Ui, icon: &str, title: &str, description: &str) -> bool {
    // Reserve the full width and detect hover/click on the whole area
    let desired_size = egui::vec2(ui.available_width(), STARTUP_CARD_HEIGHT);
    let (rect, response) = ui.allocate_exact_size(desired_size, egui::Sense::click());

    // Choose fill color based on hover
    let fill = if response.hovered() {
        ui.style().visuals.widgets.hovered.bg_fill
    } else {
        ui.style().visuals.widgets.inactive.bg_fill
    };

    let frame = egui::Frame::group(ui.style()).fill(fill);
    ui.scope_builder(egui::UiBuilder::new().max_rect(rect), |ui| {
        frame.show(ui, |ui| {
            // Prevent child labels/icons from showing their own hover cursor and
            // highlight, so the entire card acts as a single clickable area.
            ui.style_mut().interaction.selectable_labels = false;
            ui.set_width(ui.available_width());
            ui.vertical_centered(|ui| {
                ui.add_space(SPACING_LG);
                ui.label(egui::RichText::new(icon).size(ICON_SIZE_LG));
                ui.add_space(SPACING_SM);
                ui.strong(egui::RichText::new(title).size(TEXT_SIZE_LG));
                ui.add_space(SPACING_XS);
                ui.label(
                    egui::RichText::new(description)
                        .size(TEXT_SIZE_SM)
                        .color(COLOR_TEXT_MUTED),
                );
                ui.add_space(SPACING_LG);
            });
        });
    });

    if response.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }

    response.clicked()
}

fn render_startup_modal(ctx: &egui::Context, state: &mut ConfigurationFileState) {
    match state.modal_state {
        StartupModalState::Initial => render_initial_modal(ctx, state),
        StartupModalState::TemplateSelection => render_template_selection_modal(ctx, state),
    }
}

fn render_initial_modal(ctx: &egui::Context, state: &mut ConfigurationFileState) {
    // Use the same modal ID as template selection to avoid flicker when transitioning
    egui::Modal::new(egui::Id::new("startup_modal")).show(ctx, |ui| {
        ui.set_width(MODAL_WIDTH_MD);
        ui.heading("Welcome to Fos-R");
        ui.add_space(SPACING_SM);
        ui.label("Choose a configuration to get started:");
        ui.add_space(SPACING_XL);

        ui.columns(STARTUP_COLUMNS_INITIAL, |cols| {
            // Left: default config
            if startup_card(
                &mut cols[0],
                egui_material_icons::icons::ICON_LAN,
                "Default configuration",
                "Choose from preset templates\nfor different network types",
            ) {
                state.modal_state = StartupModalState::TemplateSelection;
            }

            // Right: import file
            if startup_card(
                &mut cols[1],
                egui_material_icons::icons::ICON_UPLOAD_FILE,
                "Import YAML file",
                "Load your own network\nconfiguration from a file",
            ) {
                trigger_file_import(state, cols[1].ctx());
            }
        });

        #[cfg(target_arch = "wasm32")]
        poll_file_import(state);
    });
}

fn render_template_selection_modal(ctx: &egui::Context, state: &mut ConfigurationFileState) {
    // Use the same modal ID as initial modal to avoid flicker when transitioning
    egui::Modal::new(egui::Id::new("startup_modal")).show(ctx, |ui| {
        ui.set_width(MODAL_WIDTH_MD);

        // Header with back button
        ui.horizontal(|ui| {
            if ui
                .button(egui_material_icons::icons::ICON_ARROW_BACK)
                .on_hover_text("Back")
                .clicked()
            {
                state.modal_state = StartupModalState::Initial;
            }
            ui.heading("Choose a template");
        });

        ui.add_space(SPACING_XL);

        // Grid of template cards
        let templates = all_templates();
        ui.columns(STARTUP_COLUMNS_TEMPLATES, |cols| {
            for (i, template) in templates.iter().enumerate() {
                if startup_card(
                    &mut cols[i % STARTUP_COLUMNS_TEMPLATES],
                    template.icon,
                    template.title,
                    template.description,
                ) {
                    load_template_by_id(state, template.id);
                }
            }
        });
    });
}
