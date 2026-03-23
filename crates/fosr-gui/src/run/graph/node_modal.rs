//! Node click handling and info/edit modal for the visualization graph.

use super::state::{NodeType, VisualizationState};
use crate::shared::assets::{IMG_COMPUTER, IMG_INTERNET, IMG_SERVER};
use crate::shared::colors::{COLOR_ICON_TINT_DARK, COLOR_ICON_TINT_LIGHT};
use crate::shared::config::state::ConfigurationFileState;
use crate::shared::ui_constants::{
    INDENT_STANDARD, LEGEND_ICON_SIZE, NODE_MODAL_WIDTH, SPACING_LG, SPACING_SM,
};
use eframe::egui;
use egui_graphs::events::{Event, PayloadNodeClick};

/// Process graph click events from the event buffer
pub fn process_graph_events(
    state: &mut VisualizationState,
    configuration_file_state: &ConfigurationFileState,
) {
    let events: Vec<Event> = state.events_buffer.borrow_mut().drain(..).collect();

    for event in events {
        if let Event::NodeClick(PayloadNodeClick { id }) = event {
            let node_idx = petgraph::graph::NodeIndex::new(id);
            state.clicked_node = Some(node_idx);
            state.node_info_modal_open = true;

            // Clone the host into the edit buffer
            let host_idx = state.node_to_host.get(&node_idx).copied();
            state.modal_edit_buffer = host_idx.and_then(|idx| {
                configuration_file_state
                    .config_model
                    .as_ref()
                    .and_then(|c| c.hosts.get(idx).cloned())
            });
        }
    }
}

/// Render the node information modal for the clicked node
pub fn render_node_info_modal(
    ctx: &egui::Context,
    state: &mut VisualizationState,
    config_file_state: &mut ConfigurationFileState,
) {
    if !state.node_info_modal_open {
        return;
    }

    let Some(node_idx) = state.clicked_node else {
        return;
    };

    let Some(node) = state.graph.g().node_weight(node_idx) else {
        state.node_info_modal_open = false;
        state.clicked_node = None;
        return;
    };

    let node_data = node.payload().clone();
    let host_idx = state.node_to_host.get(&node_idx).copied();
    let has_edit_buffer = state.modal_edit_buffer.is_some();

    let mut save_clicked = false;
    let modal = egui::Modal::new(egui::Id::new("node_info_modal")).show(ctx, |ui| {
        ui.set_width(NODE_MODAL_WIDTH);
        if has_edit_buffer {
            ui.heading("Edit Node Information");
        } else {
            ui.heading("Node Information");
        }

        ui.separator();

        // Node type with icon
        ui.horizontal(|ui| {
            let (image, type_str) = match node_data.node_type {
                NodeType::Server => (IMG_SERVER, "Server"),
                NodeType::User => (IMG_COMPUTER, "User"),
                NodeType::Internet => (IMG_INTERNET, "Internet"),
            };
            let tint = if ui.style().visuals.dark_mode {
                COLOR_ICON_TINT_DARK
            } else {
                COLOR_ICON_TINT_LIGHT
            };
            ui.add(
                egui::Image::new(image)
                    .fit_to_exact_size(egui::vec2(LEGEND_ICON_SIZE, LEGEND_ICON_SIZE))
                    .tint(tint),
            );
            ui.label(egui::RichText::new(type_str).strong());
        });

        ui.add_space(SPACING_SM);

        // Editable fields if we have an edit buffer (config loaded and host found)
        if let Some(ref mut host) = state.modal_edit_buffer {
            // Hostname
            ui.horizontal(|ui| {
                ui.label("Hostname:");
                let mut buf = host.hostname.clone().unwrap_or_default();
                if ui
                    .add(egui::TextEdit::singleline(&mut buf).hint_text("hostname"))
                    .changed()
                {
                    host.hostname = if buf.trim().is_empty() {
                        None
                    } else {
                        Some(buf)
                    };
                }
            });

            // OS
            ui.horizontal(|ui| {
                ui.label("OS:");
                let selected = host.os.as_deref().unwrap_or("<none>");
                egui::ComboBox::from_id_salt("modal_os")
                    .selected_text(selected)
                    .show_ui(ui, |ui| {
                        if ui.selectable_label(host.os.is_none(), "<none>").clicked() {
                            host.os = None;
                        }
                        if ui
                            .selectable_label(host.os.as_deref() == Some("Linux"), "Linux")
                            .clicked()
                        {
                            host.os = Some("Linux".to_string());
                        }
                        if ui
                            .selectable_label(host.os.as_deref() == Some("Windows"), "Windows")
                            .clicked()
                        {
                            host.os = Some("Windows".to_string());
                        }
                    });
            });

            // IP addresses
            ui.label("IP Addresses:");
            for iface in &mut host.interfaces {
                ui.horizontal(|ui| {
                    ui.add_space(INDENT_STANDARD);
                    ui.add(egui::TextEdit::singleline(&mut iface.ip_addr).hint_text("0.0.0.0"));
                });
            }
        } else {
            // Read-only fallback (no config loaded or Internet node)
            if let Some(ref hostname) = node_data.hostname {
                ui.horizontal(|ui| {
                    ui.label("Hostname:");
                    ui.label(egui::RichText::new(hostname).monospace());
                });
            }
            // Don't show OS or IP for Internet node
            if node_data.node_type != NodeType::Internet {
                ui.horizontal(|ui| {
                    ui.label("OS:");
                    ui.label(egui::RichText::new(format!("{:?}", node_data.os)).monospace());
                });
                ui.label("IP Addresses:");
                for ip in &node_data.ip_addrs {
                    ui.horizontal(|ui| {
                        ui.add_space(INDENT_STANDARD);
                        ui.label(egui::RichText::new(ip.to_string()).monospace());
                    });
                }
            }
        }

        ui.add_space(SPACING_LG);

        if has_edit_buffer {
            ui.horizontal(|ui| {
                if ui
                    .button(egui_material_icons::icons::ICON_CLOSE)
                    .on_hover_text("Cancel")
                    .clicked()
                {
                    ui.close();
                }
                if ui
                    .button(egui_material_icons::icons::ICON_SAVE)
                    .on_hover_text("Save")
                    .clicked()
                {
                    save_clicked = true;
                    ui.close();
                }
            });
        } else {
            if ui
                .button(egui_material_icons::icons::ICON_CLOSE)
                .on_hover_text("Close")
                .clicked()
            {
                ui.close();
            }
        }
    });

    // Apply changes to config model on Save
    if save_clicked {
        if let (Some(idx), Some(buffer)) = (host_idx, state.modal_edit_buffer.take()) {
            if let Some(host) = config_file_state
                .config_model
                .as_mut()
                .and_then(|c| c.hosts.get_mut(idx))
            {
                *host = buffer;
            }
            // Sync config model back to YAML so other tabs and handle_config_changes pick it up
            if let Some(model) = &config_file_state.config_model {
                if let Ok(yaml) = serde_yaml::to_string(model) {
                    config_file_state.config_file_content = Some(yaml);
                }
            }
        }
    }

    // Close on Escape or click outside (discard changes)
    if modal.should_close() {
        state.node_info_modal_open = false;
        state.clicked_node = None;
        state.modal_edit_buffer = None;
    }
}
