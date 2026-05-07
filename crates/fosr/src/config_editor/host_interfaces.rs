//! Network interface editing UI: IP, MAC address, associated services, and uses.

use crate::config_editor::host_services;
use egui_material_icons::icons::{ICON_ADD, ICON_DELETE};
use fosr_lib::network::{HostYaml, InterfaceYaml};
use fosr_lib::structs::L7Proto;
use crate::shared::constants::colors::COLOR_ERROR;
use crate::shared::constants::network::{
    MAC_ADDRESS_BYTES, MAC_LOCAL_BIT, MAC_LOCAL_MASK,
};
use crate::shared::constants::ui::{MULTI_SELECT_PICKER_WIDTH, SPACING_MD, SPACING_SM};
use crate::shared::widgets::helpers::{info_icon_with_tooltip, render_optional_string_input, required_label};
use crate::shared::widgets::multi_select_picker::multi_select_picker;
use eframe::egui;
use std::collections::HashMap;
use std::net::Ipv4Addr;

/// Find the next available IP within a given subnet/mask.
pub fn find_available_ip_in_subnet(
    subnet: Ipv4Addr,
    mask: u8,
    ip_counts: &HashMap<String, usize>,
) -> Option<String> {
    let subnet_u32 = u32::from(subnet);
    let host_bits = 32 - mask as u32;

    // Number of assignable host IPs (exclude network address and broadcast).
    // For a /24: (2^8) - 2 = 254 addresses (192.168.0.1 through 192.168.0.254).
    let num_hosts = (1u32 << host_bits) - 2;

    for i in 1..=num_hosts {
        // Build the candidate IP from the subnet prefix + host offset:
        //
        //   (1u32 << host_bits) - 1      → host part mask (low bits all 1s)
        //   !((1u32 << host_bits) - 1)   → network part mask (high bits all 1s, low bits 0s)
        //   subnet_u32 & network_mask    → zero out the host part, keep the network prefix
        //   ... | i                      → set host part to the i-th address
        //
        // Example with subnet 192.168.1.0/24 (host_bits = 8):
        //   network_mask = 0xFFFFFF00
        //   subnet_u32 & network_mask    = 192.168.1.0 (clear host octet)
        //   ... | 5                      = 192.168.1.5 (i-th host)
        let network_mask = !((1u32 << host_bits) - 1);
        let candidate_u32 = (subnet_u32 & network_mask) | i;
        let candidate = Ipv4Addr::from(candidate_u32);
        let candidate_str = candidate.to_string();
        if !ip_counts.contains_key(&candidate_str) {
            return Some(candidate_str);
        }
    }
    None
}

/// Interface section rendering
pub fn render_interfaces_section(
    ui: &mut egui::Ui,
    host_idx: usize,
    host: &mut HostYaml,
    ip_counts: &HashMap<String, usize>,
    mac_counts: &HashMap<String, usize>,
    subnet_ctx: Option<(Ipv4Addr, u8)>,
) {
    ui.horizontal(|ui| {
        ui.label("Interfaces");
        if ui
            .button(ICON_ADD)
            .on_hover_text("Add interface")
            .clicked()
        {
            let ip = subnet_ctx
                .and_then(|(subnet, mask)| find_available_ip_in_subnet(subnet, mask, ip_counts));

            match (ip, subnet_ctx) {
                (Some(ip), _) => {
                    host.interfaces.insert(0, InterfaceYaml {
                        ip_addr: ip,
                        mac_addr: Some(generate_mac_until_unique(mac_counts)),
                        services: Some(Vec::new()),
                        uses: None,
                    });
                }
                (None, None) => {
                    // Internet host: no subnet context, create interface with empty IP
                    host.interfaces.insert(0, InterfaceYaml {
                        ip_addr: String::new(),
                        mac_addr: Some(generate_mac_until_unique(mac_counts)),
                        services: Some(Vec::new()),
                        uses: None,
                    });
                }
                (None, Some(_)) => {
                    ui.colored_label(COLOR_ERROR, "No free IP available in this subnet");
                }
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
    interface: &mut InterfaceYaml,
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
                    .button(ICON_DELETE)
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
    interface: &mut InterfaceYaml,
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

    // Uses section - multi-select picker for protocols the host can use
    {
        let protocol_names = L7Proto::all_names();
        let protocol_name_refs: Vec<&str> = protocol_names.iter().map(|s| s.as_str()).collect();

        let mut selected: Vec<String> = interface.uses.clone().unwrap_or_default();

        ui.horizontal(|ui| {
            ui.label("Uses");
            info_icon_with_tooltip(ui, "Specify what protocols the host can use through this interface.");

            let picker_id = ui.make_persistent_id(("uses_picker", host_idx, interface_idx));
            multi_select_picker(
                ui,
                picker_id,
                &protocol_name_refs,
                &mut selected,
                MULTI_SELECT_PICKER_WIDTH,
            );
        });

        interface.uses = if selected.is_empty() {
            None
        } else {
            Some(selected)
        };
    }
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
pub fn generate_mac_until_unique(mac_counts: &HashMap<String, usize>) -> String {
    loop {
        let mac = generate_local_mac();

        if !mac_counts.contains_key(&mac) {
            return mac;
        }
    }
}
