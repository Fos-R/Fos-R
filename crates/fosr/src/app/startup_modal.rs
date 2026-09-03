//! Startup modal for choosing configuration source (templates or import).

use crate::app::{FosrApp, ViewState};
use crate::config_templates::{load_empty_config, load_template};
use crate::shared::assets::IMG_LOGO;
#[cfg(target_arch = "wasm32")]
use crate::shared::config::file_ops::poll_file_import;
use crate::shared::config::file_ops::trigger_file_import;
use crate::shared::constants::colors::COLOR_TEXT_MUTED;
use crate::shared::constants::ui::*;
use crate::shared::widgets::helpers::info_icon_with_tooltip;
use eframe::egui;
use egui_material_icons::icons::{
    ICON_ARROW_BACK, ICON_EDIT, ICON_LAN, ICON_MAGIC_BUTTON, ICON_PLAY_ARROW, ICON_UPLOAD_FILE,
};
use std::sync::mpsc::{TryRecvError, channel};
#[cfg(not(target_arch = "wasm32"))]
use std::thread;

/// Builds the frame style for a startup card based on hover state.
fn card_frame_for_hover(ui: &egui::Ui, is_hovered: bool) -> egui::Frame {
    let fill = if is_hovered {
        ui.style().visuals.widgets.hovered.bg_fill
    } else {
        ui.style().visuals.widgets.inactive.bg_fill
    };
    egui::Frame::group(ui.style()).fill(fill)
}

/// Renders the centered content inside a startup card (icon, title, description).
fn render_card_content(ui: &mut egui::Ui, icon: Option<&str>, title: &str, description: &str) {
    // Disable text selection so the whole card acts as a single clickable area
    ui.style_mut().interaction.selectable_labels = false;
    ui.set_width(ui.available_width());
    ui.set_height(ui.available_height());

    ui.vertical_centered(|ui| {
        ui.add_space(SPACING_LG);
        if let Some(icon) = icon {
            ui.label(egui::RichText::new(icon).size(ICON_SIZE_LG));
            ui.add_space(SPACING_SM);
        }
        ui.strong(egui::RichText::new(title).size(TEXT_SIZE_LG));
        ui.add_space(SPACING_XS);
        ui.label(
            egui::RichText::new(description)
                .size(TEXT_SIZE_SM)
                .color(COLOR_TEXT_MUTED),
        );
        ui.add_space(SPACING_LG);
    });
}

/// A clickable card with icon, title and description.
/// Returns true if the card was clicked.
fn startup_card(
    ui: &mut egui::Ui,
    icon: Option<&str>,
    title: &str,
    description: &str,
    min_height: f32,
) -> bool {
    let desired_size = egui::vec2(ui.available_width(), min_height);
    let (rect, response) = ui.allocate_exact_size(desired_size, egui::Sense::click());

    let frame = card_frame_for_hover(ui, response.hovered());
    ui.scope_builder(egui::UiBuilder::new().max_rect(rect), |ui| {
        frame.show(ui, |ui| {
            render_card_content(ui, icon, title, description);
        });
    });

    if response.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }

    response.clicked()
}

/// Renders the initial modal with options to use templates or import a file.
pub fn render_initial_modal(ctx: &egui::Context, state: &mut FosrApp) -> bool {
    // Use the same modal ID as template selection to avoid flicker when transitioning
    egui::Modal::new(egui::Id::new("startup_modal"))
        .show(ctx, |ui| {
            ui.set_width(MODAL_WIDTH_MD);
            ui.columns(2, |cols| {
                cols[0].heading("Welcome!");
                cols[0].add_space(SPACING_SM);
                cols[0].label("Select a network to get started");
                cols[0].add_space(SPACING_XL);
                cols[1].add(egui::Image::new(IMG_LOGO));
            });

            ui.columns(STARTUP_COLUMNS_INITIAL, |cols| {
                // Left: empty config
                if startup_card(
                    &mut cols[0],
                    Some(ICON_EDIT),
                    "Empty network",
                    "Start from scratch with an empty network",
                    STARTUP_CARD_INITIAL_HEIGHT,
                ) {
                    load_empty_config(&mut state.config_file_state);
                    state.change_view(ViewState::ConfigTab);
                }

                // Middle: default config (templates)
                if startup_card(
                    &mut cols[1],
                    Some(ICON_LAN),
                    "Default network",
                    "Choose from presets of different network types",
                    STARTUP_CARD_INITIAL_HEIGHT,
                ) {
                    state.change_view(ViewState::TemplateSelection)
                    // state.modal_state = StartupModalStep::TemplateSelection;
                }
            });

            ui.add_space(SPACING_SM);
            ui.columns(STARTUP_COLUMNS_INITIAL, |cols| {
                if startup_card(
                    &mut cols[0],
                    Some(ICON_MAGIC_BUTTON),
                    "Synthetic network",
                    "Generate a network from constraints",
                    STARTUP_CARD_INITIAL_HEIGHT,
                ) {
                    state.change_view(ViewState::TemplateGeneration);
                    // state.change_view(ViewState::TemplateSelection)
                    // state.modal_state = StartupModalStep::TemplateSelection;
                }

                // Right: import file
                if startup_card(
                    &mut cols[1],
                    Some(ICON_UPLOAD_FILE),
                    "Import YAML file",
                    "Load a network configuration from a file",
                    STARTUP_CARD_INITIAL_HEIGHT,
                ) {
                    trigger_file_import(&mut state.config_file_state, cols[1].ctx());
                }
            });

            #[cfg(target_arch = "wasm32")]
            poll_file_import(&mut state.config_file_state);
        })
        .should_close()
}

pub fn render_template_generation(ctx: &egui::Context, state: &mut FosrApp) {
    // Use the same modal ID as initial modal to avoid flicker when transitioning
    egui::Modal::new(egui::Id::new("startup_modal")).show(ctx, |ui| {
        ui.set_width(MODAL_WIDTH_MD_TEMPLATE_GENERATION);

        // Header with back button
        ui.horizontal(|ui| {
            if ui.button(ICON_ARROW_BACK).on_hover_text("Back").clicked() {
                state.change_view(ViewState::Welcome);
            }
            ui.heading("Generate a network");
        });
        ui.separator();

        // ui.horizontal(|ui| {
        //     ui.checkbox(&mut state.network_generation_options, "");
        //     info_icon_with_tooltip(ui, "Beginning time of the pcap. By default, use the current time. For deterministic generation, you must specify this along with duration, timezone and seed.");
        //     ui.checkbox(&mut state.network_generation_options, "");
        //     info_icon_with_tooltip(ui, "Beginning time of the pcap. By default, use the current time. For deterministic generation, you must specify this along with duration, timezone and seed.");

        // });
        ui.label("Services present in the network");
        ui.add_space(SPACING_SM);
        ui.columns(3, |cols| {
            cols[0].checkbox(&mut state.topology_generation.with_web_server, "Web server");
            cols[1].checkbox(&mut state.topology_generation.with_ftp_server, "FTP server");
            cols[2].checkbox(
                &mut state.topology_generation.with_mail_server,
                "Mail server",
            );
        });
        ui.add_space(SPACING_SM);
        ui.columns(3, |cols| {
            cols[0].checkbox(
                &mut state.topology_generation.with_cloud_storage,
                "Cloud storage",
            );
            cols[1].checkbox(&mut state.topology_generation.with_log_server, "Log server");
            cols[2].checkbox(
                &mut state.topology_generation.with_dbms_server,
                "DBMS server",
            );
        });
        ui.add_space(SPACING_SM);
        ui.columns(3, |cols| {
            cols[0].checkbox(&mut state.topology_generation.with_cms_server, "CMS server");
            cols[1].checkbox(
                &mut state.topology_generation.with_proxy_server,
                "Proxy server",
            );
            cols[2].checkbox(
                &mut state.topology_generation.with_ldap_server,
                "LDAP server",
            );
        });
        ui.add_space(SPACING_SM);
        ui.columns(3, |cols| {
            cols[0].checkbox(&mut state.topology_generation.with_ssh_server, "SSH server");
            cols[1].checkbox(&mut state.topology_generation.with_dns_server, "DNS server");
        });

        ui.add_space(SPACING_XL);
        ui.horizontal(|ui| {
            ui.checkbox(
                &mut state.topology_generation.internet_access,
                "Internet access",
            );
            info_icon_with_tooltip(
                ui,
                "Ensure the network has a public IP and generate flows to and from the Internet.",
            );
        });

        ui.add_space(SPACING_XL);
        ui.add(
            egui::Slider::new(&mut state.topology_generation.min_subnets, 1..=50)
                .text("Minimum number of subnets")
                .logarithmic(true),
        );
        ui.add_space(SPACING_SM);
        ui.add(
            egui::Slider::new(&mut state.topology_generation.min_nodes, 1..=500)
                .text("Minimum number of machines")
                .logarithmic(true),
        );

        ui.add_space(SPACING_LG);

        let accent = ui.visuals().selection.bg_fill;
        let button = egui::Button::new(
            egui::RichText::new(format!("{} Generate", ICON_PLAY_ARROW)).size(TEXT_SIZE_MD),
        )
        .fill(accent);

        ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
            if ui
                .add_enabled(state.topo_receiver.is_none(), button)
                .on_hover_text("Generate topology from constraints")
                .clicked()
            {
                let (send, recv) = channel();
                let ctx = ctx.clone();
                state.topology_generation.generation_failed = false;
                state.topo_receiver = Some(recv);
                let default_subtopo = state.default_subtopo.clone();
                log::info!("Starting topology generation");
                let params = state.topology_generation.get_generation_parameters();
                let task = move || {
                    match fosr_lib::topo::generator::generate_topology(&default_subtopo, &params) {
                        Ok(topo) => {
                            log::info!("Successful topology generation");
                            send.send(fosr_lib::network::NetworkYaml::from(topo))
                                .unwrap();
                        }
                        Err(e) => {
                            log::error!("Error during topology generation: {e}");
                            drop(send);
                        }
                    }
                    ctx.request_repaint();
                };

                #[cfg(target_arch = "wasm32")]
                wasm_bindgen_futures::spawn_local(async move { task() });

                #[cfg(not(target_arch = "wasm32"))]
                std::thread::spawn(task);
            }

            ui.add_space(SPACING_XXL);
            if state.topology_generation.generation_failed {
                ui.label(egui::RichText::new("Generation failed!").italics());
            }

            let mut delete_recv = false;
            if let Some(ref recv) = state.topo_receiver {
                ui.label(egui::RichText::new("Generation in progress, please wait...").italics());
                match recv.try_recv() {
                    Ok(topo) => {
                        load_template(&mut state.config_file_state, &topo);
                        state.change_view(ViewState::GraphTab);
                        delete_recv = true;
                    }
                    Err(TryRecvError::Disconnected) => {
                        state.topology_generation.generation_failed = true;
                        delete_recv = true;
                    }
                    Err(TryRecvError::Empty) => {} // still waiting
                }
            }
            if delete_recv {
                state.topo_receiver = None;
            }
        });
    });
}

/// Renders the template selection modal with preset network configurations.
pub fn render_template_selection_modal(ctx: &egui::Context, state: &mut FosrApp) {
    // Use the same modal ID as initial modal to avoid flicker when transitioning
    egui::Modal::new(egui::Id::new("startup_modal")).show(ctx, |ui| {
        ui.set_width(MODAL_WIDTH_MD_TEMPLATE_SELECTION);

        // Header with back button
        ui.horizontal(|ui| {
            if ui.button(ICON_ARROW_BACK).on_hover_text("Back").clicked() {
                state.change_view(ViewState::Welcome);
            }
            ui.heading("Choose a default network");
        });
        ui.separator();

        ui.add_space(SPACING_XL);

        let mut new_view: Option<ViewState> = None;
        // Grid of template cards
        ui.columns(STARTUP_COLUMNS_TEMPLATES, |cols| {
            for (i, template) in state.default_topologies.iter().enumerate() {
                if startup_card(
                    &mut cols[i % STARTUP_COLUMNS_TEMPLATES],
                    None,
                    &template.metadata.title,
                    &template
                        .metadata
                        .desc
                        .clone()
                        .unwrap_or("No description".to_string()),
                    STARTUP_CARD_TEMPLATE_HEIGHT,
                ) {
                    load_template(&mut state.config_file_state, template);
                    new_view = Some(ViewState::GraphTab);
                }
            }
        });
        if let Some(view) = new_view {
            state.change_view(view);
        }
    });
}
