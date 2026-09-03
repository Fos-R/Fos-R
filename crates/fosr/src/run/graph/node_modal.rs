//! Node click handling and info/edit modal for the visualization graph.

use super::state::{INTERNET_HOST_SENTINEL, NetworkNode, NodeType, VisualizationState};
use crate::shared::assets::{IMG_COMPUTER, IMG_INTERNET, IMG_ROUTER, IMG_SERVER};
use crate::shared::config::state::ConfigFileState;
use crate::shared::constants::colors::{COLOR_ICON_TINT_DARK, COLOR_ICON_TINT_LIGHT};
use crate::shared::constants::ui::{
    INDENT_STANDARD, LEGEND_ICON_SIZE, NODE_MODAL_WIDTH, SPACING_LG, SPACING_SM,
};
use crate::shared::widgets::helpers::os_display_name;
use eframe::egui;
use egui_graphs::events::{Event, PayloadNodeClick};
use egui_material_icons::icons::{ICON_CLOSE, ICON_SAVE};
use fosr_lib::network::{HostYaml, NetworkYaml};
use fosr_lib::structs::OS;

/// Look up a host by `(net_idx, host_idx)` position.
fn get_host_by_pos(model: &NetworkYaml, pos: (usize, usize)) -> Option<&HostYaml> {
    let (net_idx, h_idx) = pos;
    if net_idx == INTERNET_HOST_SENTINEL {
        model.internet.get(h_idx)
    } else {
        model.networks.get(net_idx).and_then(|n| n.hosts.get(h_idx))
    }
}

/// Look up a host by `(net_idx, host_idx)` position, mutably.
fn get_host_by_pos_mut(model: &mut NetworkYaml, pos: (usize, usize)) -> Option<&mut HostYaml> {
    let (net_idx, h_idx) = pos;
    if net_idx == INTERNET_HOST_SENTINEL {
        model.internet.get_mut(h_idx)
    } else {
        model
            .networks
            .get_mut(net_idx)
            .and_then(|n| n.hosts.get_mut(h_idx))
    }
}

/// Process graph click events from the event buffer.
pub fn process_graph_events(
    state: &mut VisualizationState,
    configuration_file_state: &ConfigFileState,
) {
    let events: Vec<Event> = state.modal.events_buffer.borrow_mut().drain(..).collect();

    for event in events {
        if let Event::NodeClick(PayloadNodeClick { id }) = event {
            let node_idx = petgraph::graph::NodeIndex::new(id);
            state.modal.clicked_node = Some(node_idx);
            state.modal.open = true;

            // Clone the host into the edit buffer
            let host_pos = state.network.node_to_host.get(&node_idx).copied();
            state.modal.edit_buffer = host_pos.and_then(|pos| {
                configuration_file_state
                    .get_config_model()
                    .as_ref()
                    .and_then(|c| get_host_by_pos(c, pos).cloned())
            });
        }
    }
}

/// Render the node information modal for the clicked node.
pub fn render_node_info_modal(
    ctx: &egui::Context,
    state: &mut VisualizationState,
    config_file_state: &mut ConfigFileState,
) {
    if !state.modal.open {
        return;
    }

    let Some(node_idx) = state.modal.clicked_node else {
        return;
    };

    let Some(node) = state.network.graph.g().node_weight(node_idx) else {
        state.modal.open = false;
        state.modal.clicked_node = None;
        return;
    };

    let node_data = node.payload().clone();
    let host_pos = state.network.node_to_host.get(&node_idx).copied();
    let has_edit_buffer = state.modal.edit_buffer.is_some();

    let mut save_clicked = false;
    let modal = egui::Modal::new(egui::Id::new("node_info_modal")).show(ctx, |ui| {
        ui.set_width(NODE_MODAL_WIDTH);

        render_modal_header(ui, &node_data, has_edit_buffer);
        ui.separator();

        if let Some(ref mut host) = state.modal.edit_buffer {
            render_editable_fields(ui, host);
        } else {
            render_readonly_fields(ui, &node_data);
        }

        ui.add_space(SPACING_LG);
        render_modal_footer(ui, has_edit_buffer, &mut save_clicked);
    });

    // Apply changes to config model on Save
    if save_clicked {
        apply_changes_to_config(state, config_file_state, host_pos);
    }

    // Close on Escape or click outside (discard changes)
    if modal.should_close() {
        state.modal.open = false;
        state.modal.clicked_node = None;
        state.modal.edit_buffer = None;
    }
}

/// Render modal header with title and node type icon.
fn render_modal_header(ui: &mut egui::Ui, node_data: &NetworkNode, has_edit_buffer: bool) {
    let title = if has_edit_buffer {
        "Edit Node Information"
    } else {
        "Node Information"
    };
    ui.heading(title);

    // Node type with icon
    ui.horizontal(|ui| {
        let (image, type_str) = match node_data.node_type {
            NodeType::Server => (IMG_SERVER, "Server"),
            NodeType::User => (IMG_COMPUTER, "User"),
            NodeType::Router => (IMG_ROUTER, "Router"),
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
}

/// Render editable fields for the host (hostname, OS, IPs).
fn render_editable_fields(ui: &mut egui::Ui, host: &mut HostYaml) {
    render_hostname_field(ui, host);
    render_os_dropdown(ui, host);
    render_ip_fields(ui, host);
}

/// Render editable hostname field.
fn render_hostname_field(ui: &mut egui::Ui, host: &mut HostYaml) {
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
}

/// Render editable OS dropdown.
fn render_os_dropdown(ui: &mut egui::Ui, host: &mut HostYaml) {
    ui.horizontal(|ui| {
        ui.label("OS:");
        let selected = os_display_name(host.os).to_string();
        egui::ComboBox::from_id_salt("modal_os")
            .selected_text(selected)
            .show_ui(ui, |ui| {
                if ui
                    .selectable_label(host.os.is_none(), os_display_name(None))
                    .clicked()
                {
                    host.os = None;
                }
                if ui
                    .selectable_label(host.os == Some(OS::Linux), os_display_name(Some(OS::Linux)))
                    .clicked()
                {
                    host.os = Some(OS::Linux);
                }
                if ui
                    .selectable_label(
                        host.os == Some(OS::Windows),
                        os_display_name(Some(OS::Windows)),
                    )
                    .clicked()
                {
                    host.os = Some(OS::Windows);
                }
            });
    });
}

/// Render editable IP address fields.
fn render_ip_fields(ui: &mut egui::Ui, host: &mut HostYaml) {
    ui.label("IP Addresses:");
    for interface in &mut host.interfaces {
        ui.horizontal(|ui| {
            ui.add_space(INDENT_STANDARD);
            ui.add(egui::TextEdit::singleline(&mut interface.ip_addr).hint_text("0.0.0.0"));
        });
    }
}

/// Render read-only fields (no config loaded or Internet node).
fn render_readonly_fields(ui: &mut egui::Ui, node_data: &NetworkNode) {
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
            ui.label(egui::RichText::new(node_data.os.to_string()).monospace());
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

/// Render modal footer with action buttons.
fn render_modal_footer(ui: &mut egui::Ui, has_edit_buffer: bool, save_clicked: &mut bool) {
    if has_edit_buffer {
        ui.horizontal(|ui| {
            if ui.button(ICON_CLOSE).on_hover_text("Cancel").clicked() {
                ui.close();
            }
            if ui.button(ICON_SAVE).on_hover_text("Save").clicked() {
                *save_clicked = true;
                ui.close();
            }
        });
    } else {
        if ui.button(ICON_CLOSE).on_hover_text("Close").clicked() {
            ui.close();
        }
    }
}

/// Apply changes from edit buffer back to the config model.
///
/// Uses the `(net_idx, host_idx)` pair from `node_to_host` to find the host
/// in `NetworkYaml`.
fn apply_changes_to_config(
    state: &mut VisualizationState,
    config_file_state: &mut ConfigFileState,
    host_pos: Option<(usize, usize)>,
) {
    if let (Some(pos), Some(buffer)) = (host_pos, state.modal.edit_buffer.take()) {
        let host_found = config_file_state
            .get_mut_config_model()
            .as_mut()
            .and_then(|c| get_host_by_pos_mut(c, pos))
            .map(|host| {
                *host = buffer;
            });

        if host_found.is_some() {
            // Sync config model back to YAML so other tabs and handle_config_changes pick it up
            config_file_state.sync_model_to_yaml();
        }
    }
}
