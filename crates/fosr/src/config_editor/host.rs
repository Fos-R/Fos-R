//! Network-scoped host editing UI: networks as collapsible sections with nested hosts.
//!
//! This module provides the visual editor for configuring networks and hosts.
//! Each network is displayed as a collapsible section with editable subnet/mask/name
//! fields, a nested list of hosts, and an "Add host" button.

use crate::config_editor::host_validation::{
    collect_other_subnets, count_addresses, find_available_subnet, validate_network_subnet_overlap,
};
use crate::config_editor::{host_interfaces, host_validation};
use crate::shared::constants::colors::COLOR_ERROR;
use crate::shared::constants::ui::{SPACING_MD, SPACING_SM};
use crate::shared::widgets::helpers::{
    info_icon_with_tooltip, os_display_name, render_optional_string_input,
};
use eframe::egui;
use egui_material_icons::icons::{ICON_ADD, ICON_CLEAR, ICON_DELETE, ICON_WARNING};
use fosr_lib::network::{HostType, InterfaceYaml, next_ui_id};
use fosr_lib::network::{HostYaml, NetworkYaml, SubNetworkYaml};
use fosr_lib::structs::OS;
use std::collections::HashMap;
use std::net::Ipv4Addr;

/// Render the full networks section with per-network collapsible sections,
/// an "Add network" button, and an "Internet" section at the bottom.
pub fn render_hosts_section(ui: &mut egui::Ui, model: &mut NetworkYaml) {
    let (ip_counts, mac_counts) = count_addresses(model);

    let mut network_to_remove: Option<usize> = None;

    if ui
        .button(format!("{} Add subnet", ICON_ADD))
        .on_hover_text("Add a new subnetwork")
        .clicked()
    {
        let net_count = model.networks.len();
        let Some(subnet) = find_available_subnet(&model.networks) else {
            log::warn!(
                "No available /24 subnet in 192.168.0.0/16 range - all 254 slots overlap with existing networks"
            );
            return;
        };

        model.add_network(SubNetworkYaml {
            ui_id: next_ui_id(),
            subnet,
            mask: 24,
            name: Some(format!("Network {}", net_count + 1)),
            hosts: vec![],
        });
    }

    // Compute subnet overlap warnings once for all networks
    let overlap_warnings: Vec<Vec<String>> = model
        .networks
        .iter()
        .enumerate()
        .map(|(i, _)| {
            let others = collect_other_subnets(&model.networks, i);
            validate_network_subnet_overlap(&model.networks[i], &others)
        })
        .collect();

    // Render each network as a collapsible section
    for (net_idx, network) in model.networks.iter_mut().enumerate() {
        render_network_section(
            ui,
            net_idx,
            network,
            &ip_counts,
            &mac_counts,
            &overlap_warnings[net_idx],
            &mut network_to_remove,
        );
        ui.add_space(SPACING_MD);
    }

    // Apply network removal after iteration
    if let Some(idx) = network_to_remove {
        model.remove_network(idx);
    }

    ui.add_space(SPACING_MD);

    // Internet section
    render_internet_section(ui, model, &ip_counts, &mac_counts);
}

/// Render a single network as a collapsible section with editable fields and nested hosts.
fn render_network_section(
    ui: &mut egui::Ui,
    net_idx: usize,
    network: &mut SubNetworkYaml,
    ip_counts: &HashMap<String, usize>,
    mac_counts: &HashMap<String, usize>,
    overlap_warnings: &[String],
    network_to_remove: &mut Option<usize>,
) {
    let host_count = network.hosts.len();
    let header_text = format!(
        "{} ({}/{}) - {} host{}",
        network.name.clone().unwrap_or("Unnamed network".to_string()),
        network.subnet,
        network.mask,
        host_count,
        if host_count != 1 { "s" } else { "" }
    );
    // Use a unique ID to properly identify a section's state to a specific network.
    // This ensures, for instance, that an opened section stays open if a new network is added.
    let id = ui.make_persistent_id(("network_section", network.ui_id));

    // Only the first network section is expanded by default.
    egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), id, net_idx == 0)
        .show_header(ui, |ui| {
            if overlap_warnings.is_empty() {
                ui.strong(&header_text);
            } else {
                let error_text = format!(
                    "{} {}\n{}",
                    ICON_WARNING,
                    header_text,
                    overlap_warnings.join("\n")
                );
                ui.colored_label(COLOR_ERROR, error_text);
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let hover_text =
                    if let Some(ref name) = network.name {
                    format!("Remove network '{}' and all its hosts", name)
                    } else {
                    format!("Remove network and all its hosts")
                    };
                if ui.button(ICON_DELETE).on_hover_text(hover_text).clicked() {
                    *network_to_remove = Some(net_idx);
                }
            });
        })
        .body(|ui| {
            // Editable network fields
            render_network_fields(ui, network);
            ui.add_space(SPACING_SM);

            // "Add host" button at top
            if ui
                .button(format!("{} Add host", ICON_ADD))
                .on_hover_text("Add host to this network")
                .clicked()
            {
                let host = create_host_with_network_ip(network, ip_counts, mac_counts);
                network.hosts.insert(0, host);
            }

            ui.add_space(SPACING_SM);

            // Render hosts
            let mut host_to_remove: Option<usize> = None;
            for (local_idx, host) in network.hosts.iter_mut().enumerate() {
                render_host_card(
                    ui,
                    (net_idx, local_idx),
                    Some((network.subnet, network.mask)),
                    host,
                    ip_counts,
                    mac_counts,
                    &mut host_to_remove,
                );
                ui.add_space(SPACING_SM);
            }
            if let Some(idx) = host_to_remove {
                network.hosts.remove(idx);
            }
        });
}

/// Render editable subnet, mask, and name fields for a network.
fn render_network_fields(ui: &mut egui::Ui, network: &mut SubNetworkYaml) {
    ui.horizontal(|ui| {
        ui.label("Subnet");
        let mut subnet_str = network.subnet.to_string();
        if ui
            .add(egui::TextEdit::singleline(&mut subnet_str).desired_width(120.0))
            .changed()
            && let Ok(ip) = subnet_str.parse()
        {
            network.subnet = ip;
        }

        ui.label("/");
        let mut mask_val = network.mask as u32;
        if ui
            .add(egui::DragValue::new(&mut mask_val).range(1..=31).speed(0.1))
            .changed()
        {
            network.mask = mask_val as u8;
        }

        // ui.label("Name");
        // ui.text_edit_singleline(&mut network.name);
    });
}

/// Render the Internet section - similar to a network section but without subnet/mask/name.
fn render_internet_section(
    ui: &mut egui::Ui,
    model: &mut NetworkYaml,
    ip_counts: &HashMap<String, usize>,
    mac_counts: &HashMap<String, usize>,
) {
    let host_count = model.internet.len();
    let id = ui.make_persistent_id("internet_section");

    egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), id, true)
        .show_header(ui, |ui| {
            ui.strong(format!(
                "Internet ({} host{})",
                host_count,
                if host_count != 1 { "s" } else { "" }
            ));
            info_icon_with_tooltip(ui, "Catch-all section for hosts outside the topology's defined networks. Assign any IP or leave it empty for a random one.");
        })
        .body(|ui| {
            if ui
                .button(format!(
                    "{} Add internet host",
                    ICON_ADD
                ))
                .on_hover_text("Add host to internet")
                .clicked()
            {
                let host = create_internet_host(mac_counts);
                model.internet.insert(0, host);
            }

            ui.add_space(SPACING_SM);

            let mut host_to_remove: Option<usize> = None;
            for (local_idx, host) in model.internet.iter_mut().enumerate() {
                render_host_card(
                    ui,
                    (model.networks.len(), local_idx), // use network count as "internet net idx"
                    None, // no subnet context
                    host,
                    ip_counts,
                    mac_counts,
                    &mut host_to_remove,
                );
                ui.add_space(SPACING_SM);
            }
            if let Some(idx) = host_to_remove {
                model.internet.remove(idx);
            }
        });
}

/// Render a single host as a collapsible card.
fn render_host_card(
    ui: &mut egui::Ui,
    key: (usize, usize),
    subnet_ctx: Option<(Ipv4Addr, u8)>,
    host: &mut HostYaml,
    ip_counts: &HashMap<String, usize>,
    mac_counts: &HashMap<String, usize>,
    remove_request: &mut Option<usize>,
) {
    let display_name = host_display_name(host);
    let mut errors = host_validation::validate_host(host, ip_counts, mac_counts);

    // Verify that the host has at least one interface in the subnet
    if let Some((subnet, mask)) = subnet_ctx
        && let Some(warning) = host_validation::validate_host_network_placement(host, subnet, mask)
    {
        errors.push(warning);
    }

    // Use a unique ID to properly identify a section's state to a specific host.
    // This ensures, for instance, that an opened section stays open if a new host is added.
    let id = ui.make_persistent_id(("host_card", host.ui_id));
    let is_first = key.1 == 0;

    egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), id, is_first)
        .show_header(ui, |ui| {
            render_host_header(ui, &display_name, &errors, host);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let hover_text = format!("Remove host '{}'", display_name);
                if ui.button(ICON_DELETE).on_hover_text(hover_text).clicked() {
                    *remove_request = Some(key.1);
                }
            });
        })
        .body(|ui| {
            render_host_basic_fields(ui, key, host);
            ui.separator();
            host_interfaces::render_interfaces_section(
                ui, key.1, host, ip_counts, mac_counts, subnet_ctx,
            );
        });
}

/// Render the host header with name, errors, and tooltip.
fn render_host_header(ui: &mut egui::Ui, display_name: &str, errors: &[String], host: &HostYaml) {
    ui.horizontal(|ui| {
        if errors.is_empty() {
            ui.label(display_name).on_hover_ui(|ui| {
                render_host_tooltip(ui, host);
            });
        } else {
            let warning_icon = ICON_WARNING;
            let error_text = errors.join(", ");
            let label_text = format!("{} {} - {}", warning_icon, display_name, error_text);

            ui.colored_label(COLOR_ERROR, label_text).on_hover_ui(|ui| {
                render_host_tooltip(ui, host);
            });
        }
    });
}

/// Render the host summary tooltip showing type, uses, and interfaces.
fn render_host_tooltip(ui: &mut egui::Ui, host: &HostYaml) {
    let host_type = host.host_type.map_or("<auto>", |ht| match ht {
        HostType::Server => "server",
        HostType::User => "user",
        HostType::Router => "router",
    });
    ui.horizontal(|ui| {
        ui.label("Type :");
        ui.strong(host_type);
    });

    // Show uses from interfaces
    // let all_uses: Vec<&str> = host
    //     .interfaces
    //     .iter()
    //     .filter_map(|i| i.uses.as_ref())
    //     .flatten()
    //     .map(String::as_str)
    //     .collect();
    // if !all_uses.is_empty() {
    //     ui.horizontal(|ui| {
    //         ui.label("Uses protocols :");
    //         ui.strong(all_uses.join(", "));
    //     });
    // }

    ui.add_space(SPACING_SM);

    ui.label("Interfaces :");
    if host.interfaces.is_empty() {
        ui.label("  No interfaces configured.");
    } else {
        for interface in &host.interfaces {
            let services_str = interface
                .services
                .as_ref()
                .map_or("no services".to_string(), |s| {
                    if s.is_empty() {
                        "no services".to_string()
                    } else {
                        s.join(", ")
                    }
                });
            ui.label(format!("  - {} ({})", interface.ip_addr, services_str));
        }
    }
}

/// Render the basic host fields: OS, hostname, and type.
fn render_host_basic_fields(ui: &mut egui::Ui, key: (usize, usize), host: &mut HostYaml) {
    render_os_dropdown(ui, key, host);
    render_optional_string_input(ui, "Hostname", &mut host.hostname, "host1");
    render_type_dropdown(ui, key, host);
}

/// Dropdown selector for the Operating System (Linux/Windows/none).
fn render_os_dropdown(ui: &mut egui::Ui, key: (usize, usize), host: &mut HostYaml) {
    ui.horizontal(|ui| {
        ui.label("OS");

        let selected_text = os_display_name(host.os);

        egui::ComboBox::from_id_salt((key, "host_os_combo"))
            .selected_text(selected_text)
            .show_ui(ui, |ui| {
                if ui
                    .selectable_label(host.os.is_none(), os_display_name(None))
                    .clicked()
                {
                    host.os = None;
                }

                ui.separator();

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

        if host.os.is_some() && ui.button(ICON_CLEAR).on_hover_text("Clear OS").clicked() {
            host.os = None;
        }
    });
}

/// Dropdown selector for host type (server/user/auto).
fn render_type_dropdown(ui: &mut egui::Ui, key: (usize, usize), host: &mut HostYaml) {
    ui.horizontal(|ui| {
        ui.label("Type");
        info_icon_with_tooltip(
            ui,
            "Defines the role of the host. A server provides services, while a user (client) \
             consumes services. If the host is a server, it must define services. If it is a user, \
             it must define client protocols (via interface 'uses'). If set to <auto>, the role is \
             determined automatically: server if at least one service is defined, otherwise user.",
        );
        let selected_text = host.host_type.map_or("<auto>", |ht| match ht {
            HostType::Server => "server",
            HostType::User => "user",
            HostType::Router => "router",
        });

        egui::ComboBox::from_id_salt((key, "host_type"))
            .selected_text(selected_text)
            .show_ui(ui, |ui| {
                if ui
                    .selectable_label(host.host_type.is_none(), "<auto>")
                    .clicked()
                {
                    host.host_type = None;
                }
                if ui
                    .selectable_label(host.host_type == Some(HostType::Server), "server")
                    .clicked()
                {
                    host.host_type = Some(HostType::Server);
                }
                if ui
                    .selectable_label(host.host_type == Some(HostType::User), "user")
                    .clicked()
                {
                    host.host_type = Some(HostType::User);
                }
                if ui
                    .selectable_label(host.host_type == Some(HostType::Router), "router")
                    .clicked()
                {
                    host.host_type = Some(HostType::Router);
                }
            });

        if ui.button(ICON_CLEAR).on_hover_text("Clear").clicked() {
            host.host_type = None;
        }
    });
}

/// Determine the display name for a host.
fn host_display_name(host: &HostYaml) -> String {
    if let Some(name) = host.hostname.as_deref()
        && !name.trim().is_empty()
    {
        return name.to_string();
    }

    if let Some(interface) = host.interfaces.first()
        && !interface.ip_addr.trim().is_empty()
    {
        return interface.ip_addr.clone();
    }

    "Unconfigured host".to_string()
}

/// Create a new host with one interface whose IP is auto-assigned from the network's subnet.
fn create_host_with_network_ip(
    network: &SubNetworkYaml,
    ip_counts: &HashMap<String, usize>,
    mac_counts: &HashMap<String, usize>,
) -> HostYaml {
    let ip = host_interfaces::find_available_ip_in_subnet(network.subnet, network.mask, ip_counts)
        .unwrap_or_default();
    HostYaml {
        interfaces: vec![InterfaceYaml {
            ip_addr: ip,
            mac_addr: Some(host_interfaces::generate_mac_until_unique(mac_counts)),
            services: Some(Vec::new()),
        }],
        ..Default::default()
    }
}

/// Create a new internet host (no subnet context, empty IP for manual entry).
fn create_internet_host(mac_counts: &HashMap<String, usize>) -> HostYaml {
    HostYaml {
        interfaces: vec![InterfaceYaml {
            ip_addr: String::new(),
            mac_addr: Some(host_interfaces::generate_mac_until_unique(mac_counts)),
            services: Some(Vec::new()),
        }],
        ..Default::default()
    }
}
