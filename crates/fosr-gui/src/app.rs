use crate::about_tab::show_about_tab_content;
use crate::configuration::configuration_tab::{
    ConfigurationTabState, show_configuration_tab_content,
};
use crate::generation::generation_tab::{GenerationTabState, show_generation_tab_content};
#[cfg(target_arch = "wasm32")]
use crate::shared::configuration_file::poll_file_import;
use crate::shared::configuration_file::{
    ConfigurationFileState, StartupModalState, trigger_file_import,
};
use crate::templates::{all_templates, load_template_by_id};
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
    About,
}

impl Default for CurrentTab {
    fn default() -> Self {
        CurrentTab::Visualization
    }
}

pub const DEFAULT_ZOOM: f32 = 1.4;

#[derive(Default)]
pub struct FosrApp {
    current_tab: CurrentTab,
    style_initialized: bool,
    images_preloaded: bool,
    configuration_file_state: ConfigurationFileState,
    configuration_tab_state: ConfigurationTabState,
    visualization_tab_state: VisualizationTabState,
    generation_tab_state: GenerationTabState,
}

impl eframe::App for FosrApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Set default zoom once
        if !self.style_initialized {
            ctx.options_mut(|option| option.zoom_factor = DEFAULT_ZOOM);
            ctx.style_mut(|s| s.interaction.tooltip_delay = 0.1);
            self.style_initialized = true;
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

        // On web, use dark theme to match with the Fos-R website's theme
        #[cfg(target_arch = "wasm32")]
        ctx.set_theme(egui::Theme::Dark);

        // Startup modal: choose configuration source
        if !self.configuration_file_state.config_chosen {
            // Render empty CentralPanel for background, then modal on top
            egui::CentralPanel::default().show(ctx, |_ui| {});
            render_startup_modal(ctx, &mut self.configuration_file_state);
            return;
        }

        // The Top Panel is logically at the top of the window.
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            // Add a Menu Bar to host the tabs buttons
            egui::MenuBar::new().ui(ui, |ui| {
                if ui
                    .selectable_label(
                        self.current_tab == CurrentTab::Visualization,
                        "Live Preview",
                    )
                    .on_hover_text("Simulation of network traffic based on the current configuration. No real traffic is generated.")
                    .clicked()
                {
                    self.current_tab = CurrentTab::Visualization;
                }
                {
                    let label_text = if self.configuration_file_state.has_errors {
                        egui::RichText::new("⚠ Configuration").color(egui::Color32::RED)
                    } else {
                        egui::RichText::new("Configuration")
                    };
                    if ui
                        .selectable_label(
                            self.current_tab == CurrentTab::Configuration,
                            label_text,
                        )
                        .on_hover_text("Edit the network configuration: hosts, interfaces, and services.")
                        .clicked()
                    {
                        self.current_tab = CurrentTab::Configuration;
                    }
                }
                if ui
                    .selectable_label(self.current_tab == CurrentTab::Generation, "Generation")
                    .on_hover_text("Generate a PCAP file from the current network configuration.")
                    .clicked()
                {
                    self.current_tab = CurrentTab::Generation;
                }
                if ui
                    .selectable_label(self.current_tab == CurrentTab::About, "About")
                    .on_hover_text("About Fos-R and its authors.")
                    .clicked()
                {
                    self.current_tab = CurrentTab::About;
                }

                // Right-align utility buttons so they sit on the opposite side of the tabs
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    // On native, show the theme switch (using system theme by default)
                    #[cfg(not(target_arch = "wasm32"))]
                    global_theme_preference_switch(ui);

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
                });
            });
        });

        // The Central Panel is the region left after adding the Top, Bottom and Side panels.
        egui::CentralPanel::default().show(ctx, |ui| {
            // Wrap in ScrollArea for vertical scrolling
            egui::ScrollArea::vertical().show(ui, |ui| {
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
                            &mut self.configuration_file_state,
                        );
                    }
                    CurrentTab::About => {
                        show_about_tab_content(ui);
                    }
                }
            });
        });
    }
}

/// A clickable card with icon, title and description. Returns true if clicked.
fn startup_card(ui: &mut egui::Ui, icon: &str, title: &str, description: &str) -> bool {
    // Reserve the full width and detect hover/click on the whole area
    let desired_size = egui::vec2(ui.available_width(), 120.0);
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
                ui.add_space(8.0);
                ui.label(egui::RichText::new(icon).size(28.0));
                ui.add_space(4.0);
                ui.strong(egui::RichText::new(title).size(16.0));
                ui.add_space(2.0);
                ui.label(
                    egui::RichText::new(description)
                        .size(12.0)
                        .color(egui::Color32::GRAY),
                );
                ui.add_space(8.0);
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
        ui.set_width(400.0);
        ui.heading("Welcome to Fos-R");
        ui.add_space(4.0);
        ui.label("Choose a configuration to get started:");
        ui.add_space(12.0);

        ui.columns(2, |cols| {
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
        ui.set_width(400.0);

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

        ui.add_space(12.0);

        // Grid of template cards
        let templates = all_templates();
        ui.columns(3, |cols| {
            for (i, template) in templates.iter().enumerate() {
                if startup_card(
                    &mut cols[i % 3],
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
