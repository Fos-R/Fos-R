use crate::configuration::service_ui;
use crate::shared::config_model::{Host, Interface};
use crate::shared::ui_utils::{edit_optional_string, required_label};
use eframe::egui;
use std::collections::HashMap;

/// Scans all interfaces to find the next available IP in 192.168.0.x
fn next_free_ip(ip_counts: &HashMap<String, usize>) -> Option<String> {
    for x in 1..=254 {
        let candidate = format!("192.168.0.{x}");
        if !ip_counts.contains_key(&candidate) {
            return Some(candidate);
        }
    }
    None
}

/// Interface section rendering
pub fn ui_interfaces_section(
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
            if let Some(ip) = next_free_ip(ip_counts) {
                host.interfaces.push(Interface {
                    ip_addr: ip,
                    mac_addr: Some(generate_mac_until_unique(mac_counts)),
                    services: Vec::new(),
                });
            } else {
                ui.colored_label(egui::Color32::RED, "No free IP available in 192.168.0.0/24");
            }
        }
    });

    if host.interfaces.is_empty() {
        ui.label("No interfaces.");
        return;
    }

    let mut iface_to_remove: Option<usize> = None;

    for (if_idx, iface) in host.interfaces.iter_mut().enumerate() {
        let ip_label = iface.ip_addr.clone();
        let id = ui.make_persistent_id(("iface", host_idx, if_idx));

        egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), id, if_idx == 0)
            .show_header(ui, |ui| {
                ui.label(format!("Interface — {ip_label}"));

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .button(egui_material_icons::icons::ICON_DELETE)
                        .on_hover_text("Remove interface")
                        .clicked()
                    {
                        iface_to_remove = Some(if_idx);
                    }
                });
            })
            .body(|ui| {
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    required_label(ui, "IP");
                    ui.text_edit_singleline(&mut iface.ip_addr);
                    if ip_counts.get(&iface.ip_addr).copied().unwrap_or(0) > 1 {
                        ui.colored_label(egui::Color32::RED, "IP already in used");
                    }
                });
                edit_optional_string(ui, "MAC", &mut iface.mac_addr, "00:14:2A:3F:47:D8");
                if let Some(mac) = &iface.mac_addr {
                    if mac_counts.get(mac).copied().unwrap_or(0) > 1 {
                        ui.colored_label(egui::Color32::RED, "MAC already in use");
                    }
                }
                service_ui::ui_services_section(ui, if_idx, host_idx, iface);
            });
        ui.add_space(6.0);
    }

    if let Some(idx) = iface_to_remove {
        host.interfaces.remove(idx);
    }
}

/// Generate a random mac address
fn random_mac() -> String {
    let mut bytes: [u8; 6] = rand::random();

    // Forcing local MAC
    bytes[0] = (bytes[0] | 0x02) & 0xFE;

    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}

fn generate_mac_until_unique(mac_counts: &HashMap<String, usize>) -> String {
    loop {
        let mac = random_mac();

        if !mac_counts.contains_key(&mac) {
            return mac;
        }
    }
}
