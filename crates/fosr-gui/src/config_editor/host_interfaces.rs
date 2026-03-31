//! Network interface editing UI: IP, MAC address, and associated services.

use crate::config_editor::host_services;
use crate::shared::config::model::{Host, Interface};
use crate::shared::constants::colors::COLOR_ERROR;
use crate::shared::constants::network::{
    IP_LOCAL_MAX, IP_LOCAL_MIN, MAC_ADDRESS_BYTES, MAC_LOCAL_BIT, MAC_LOCAL_MASK,
};
use crate::shared::constants::ui::{SPACING_MD, SPACING_SM};
use crate::shared::widgets::helpers::{render_optional_string_input, required_label};
use eframe::egui;
use std::collections::HashMap;

/// Scans all interfaces to find the next available IP in 192.168.0.x
fn find_available_ip(ip_counts: &HashMap<String, usize>) -> Option<String> {
    for x in IP_LOCAL_MIN..=IP_LOCAL_MAX {
        let candidate = format!("192.168.0.{x}");
        if !ip_counts.contains_key(&candidate) {
            return Some(candidate);
        }
    }
    None
}

/// Interface section rendering
pub fn render_interfaces_section(
    ui: &mut egui::Ui,
    host_idx: usize,
    host: &mut Host,
    ip_counts: &HashMap<String, usize>,
    mac_counts: &HashMap<String, usize>,
) {
    ui.horizontal(|ui| {
        ui.label("Interfaces");
        if ui
            .button(egui_material_icons::icons::ICON_ADD)
            .on_hover_text("Add interface")
            .clicked()
        {
            if let Some(ip) = find_available_ip(ip_counts) {
                host.interfaces.push(Interface {
                    ip_addr: ip,
                    mac_addr: Some(generate_mac_until_unique(mac_counts)),
                    services: Vec::new(),
                });
            } else {
                ui.colored_label(COLOR_ERROR, "No free IP available in 192.168.0.0/24");
            }
        }
    });

    if host.interfaces.is_empty() {
        ui.label("No interfaces.");
        return;
    }

    let mut interface_to_remove: Option<usize> = None;

    for (interface_idx, interface) in host.interfaces.iter_mut().enumerate() {
        render_interface_card(
            ui,
            host_idx,
            interface_idx,
            interface,
            ip_counts,
            mac_counts,
            &mut interface_to_remove,
        );
        ui.add_space(SPACING_MD);
    }

    if let Some(idx) = interface_to_remove {
        host.interfaces.remove(idx);
    }
}

/// Render a single interface as a collapsible card.
///
/// Shows IP address in header, with editable fields for IP, MAC, and services in the body.
fn render_interface_card(
    ui: &mut egui::Ui,
    host_idx: usize,
    interface_idx: usize,
    interface: &mut Interface,
    ip_counts: &HashMap<String, usize>,
    mac_counts: &HashMap<String, usize>,
    remove_request: &mut Option<usize>,
) {
    let ip_label = interface.ip_addr.clone();
    let id = ui.make_persistent_id(("interface", host_idx, interface_idx));

    egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), id, interface_idx == 0)
        .show_header(ui, |ui| {
            ui.label(format!("Interface - {ip_label}"));

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .button(egui_material_icons::icons::ICON_DELETE)
                    .on_hover_text("Remove interface")
                    .clicked()
                {
                    *remove_request = Some(interface_idx);
                }
            });
        })
        .body(|ui| {
            render_interface_fields(ui, host_idx, interface_idx, interface, ip_counts, mac_counts);
        });
}

/// Render the editable fields for an interface: IP, MAC, and services.
fn render_interface_fields(
    ui: &mut egui::Ui,
    host_idx: usize,
    interface_idx: usize,
    interface: &mut Interface,
    ip_counts: &HashMap<String, usize>,
    mac_counts: &HashMap<String, usize>,
) {
    ui.add_space(SPACING_SM);

    // IP address field with duplicate warning
    ui.horizontal(|ui| {
        required_label(ui, "IP");
        ui.text_edit_singleline(&mut interface.ip_addr);
        if ip_counts.get(&interface.ip_addr).copied().unwrap_or(0) > 1 {
            ui.colored_label(COLOR_ERROR, "IP already in use");
        }
    });

    // MAC address field with duplicate warning
    render_optional_string_input(ui, "MAC", &mut interface.mac_addr, "00:14:2A:3F:47:D8");
    if let Some(mac) = &interface.mac_addr {
        if mac_counts.get(mac).copied().unwrap_or(0) > 1 {
            ui.colored_label(COLOR_ERROR, "MAC already in use");
        }
    }

    // Services section
    host_services::render_services_section(ui, host_idx, interface_idx, interface);
}

/// Generate a random MAC address with the locally administered bit set.
fn generate_local_mac() -> String {
    let mut bytes: [u8; MAC_ADDRESS_BYTES] = rand::random();

    // Forcing local MAC
    bytes[0] = (bytes[0] | MAC_LOCAL_BIT) & MAC_LOCAL_MASK;

    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}

/// Generate a unique random MAC address, retrying until one not in use is found.
fn generate_mac_until_unique(mac_counts: &HashMap<String, usize>) -> String {
    loop {
        let mac = generate_local_mac();

        if !mac_counts.contains_key(&mac) {
            return mac;
        }
    }
}
