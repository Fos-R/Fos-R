//! Host editing UI: hostname, OS, type, and client protocols.

use crate::config_editor::{host_interfaces, host_services, host_validation};
use crate::shared::colors::COLOR_ERROR;
use crate::shared::config_model::{Configuration, Host};
use crate::shared::network_constants::HOST_USAGE_DEFAULT;
use crate::shared::ui_constants::{
    PANEL_MIN_WIDTH, POPUP_MAX_HEIGHT, POPUP_MIN_WIDTH, SPACING_MD, SPACING_SM,
};
use crate::shared::ui_utils::{edit_optional_string, info_icon};
use eframe::egui;
use std::collections::HashMap;

/// Several host rendering.
pub fn ui_hosts_section(ui: &mut egui::Ui, model: &mut Configuration) {
    ui.horizontal(|ui| {
        ui.heading("Hosts");
        if ui
            .button(egui_material_icons::icons::ICON_ADD)
            .on_hover_text("Add host")
            .clicked()
        {
            model.hosts.insert(0, Host::default());
        }
    });
    ui.add_space(SPACING_MD);

    if model.hosts.is_empty() {
        ui.label("No hosts in this configuration.");
        return;
    }

    // Keep track of used IP and MAC addresses
    let mut ip_counts: HashMap<String, usize> = HashMap::new();
    for h in &model.hosts {
        for iface in &h.interfaces {
            *ip_counts.entry(iface.ip_addr.clone()).or_insert(0) += 1;
        }
    }
    let mut mac_counts: HashMap<String, usize> = HashMap::new();
    for h in &model.hosts {
        for iface in &h.interfaces {
            if let Some(mac) = &iface.mac_addr {
                *mac_counts.entry(mac.clone()).or_insert(0) += 1;
            }
        }
    }

    let mut host_to_remove: Option<usize> = None;

    for (idx, host) in model.hosts.iter_mut().enumerate() {
        ui_single_host(ui, idx, host, &ip_counts, &mac_counts, &mut host_to_remove);
        ui.add_space(SPACING_MD);
    }

    if let Some(idx) = host_to_remove {
        model.hosts.remove(idx);
    }
}

/// Single host rendering
fn ui_single_host(
    ui: &mut egui::Ui,
    index: usize,
    host: &mut Host,
    ip_counts: &HashMap<String, usize>,
    mac_counts: &HashMap<String, usize>,
    remove_request: &mut Option<usize>,
) {
    let host_name = host_display_name(host);
    let errors = host_validation::validate_host(host, ip_counts, mac_counts);

    let id = ui.make_persistent_id(("host", index));
    egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), id, index == 0)
        .show_header(ui, |ui| {
            ui.horizontal(|ui| {
                if errors.is_empty() {
                    ui.label(host_name).on_hover_ui(|ui| {
                        ui_host_summary_tooltip(ui, host);
                    });
                } else {
                    let warning_icon = egui_material_icons::icons::ICON_WARNING;
                    let error_text = errors.join(", ");

                    let label_text = format!("{} {} - {}", warning_icon, host_name, error_text);
                    ui.colored_label(COLOR_ERROR, label_text)
                        .on_hover_ui(|ui| {
                            ui_host_summary_tooltip(ui, host);
                        });
                }
            });

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .button(egui_material_icons::icons::ICON_DELETE)
                    .on_hover_text("Remove host")
                    .clicked()
                {
                    *remove_request = Some(index);
                }
            });
        })
        .body(|ui| {
            ui_host_os_selector(ui, index, &mut host.os);
            edit_optional_string(ui, "Hostname", &mut host.hostname, "host1");

            ui.horizontal(|ui| {
                ui.label("Usage");
                info_icon(ui, &format!("Optional (default value: {0}). The usage intensity of the host. {0} is the baseline, < {0} means less usage than usual, and > {0} means higher usage", HOST_USAGE_DEFAULT));
                let mut usage_val = host.usage.unwrap_or(HOST_USAGE_DEFAULT);
                if ui
                    .add(egui::DragValue::new(&mut usage_val).speed(0.1))
                    .changed()
                {
                    host.usage = if (usage_val - HOST_USAGE_DEFAULT).abs() < f32::EPSILON {
                        None
                    } else {
                        Some(usage_val)
                    };
                }
                if ui
                    .button(egui_material_icons::icons::ICON_CLEAR)
                    .on_hover_text("Clear")
                    .clicked()
                {
                    host.usage = None;
                }
            });

            ui_host_type_selector(ui, index, host);
            ui_host_client_protocols(ui, index, host);
            ui.separator();
            host_interfaces::ui_interfaces_section(ui, index, host, ip_counts, mac_counts);
        });
}

/// Host summary
fn ui_host_summary_tooltip(ui: &mut egui::Ui, host: &Host) {
    let host_type = host.r#type.as_deref().unwrap_or("<auto>");
    ui.horizontal(|ui| {
        ui.label("Type :");
        ui.strong(host_type);
    });

    if !host.client.is_empty() {
        ui.horizontal(|ui| {
            ui.label("Client protocols :");
            ui.strong(host.client.join(", "));
        });
    }

    ui.add_space(SPACING_SM);

    ui.label("Interfaces :");
    if host.interfaces.is_empty() {
        ui.label("  No interfaces configured.");
    } else {
        for iface in &host.interfaces {
            let services_str = if iface.services.is_empty() {
                "no services".to_string()
            } else {
                iface.services.join(", ")
            };

            ui.label(format!("  • {} ({})", iface.ip_addr, services_str));
        }
    }
}

/// Dropdown selector for the Operating System
fn ui_host_os_selector(ui: &mut egui::Ui, host_idx: usize, host_os: &mut Option<String>) {
    ui.horizontal(|ui| {
        ui.label("OS");

        let selected_text = host_os.as_deref().unwrap_or("<none>");

        egui::ComboBox::from_id_salt((host_idx, "host_os_combo"))
            .selected_text(selected_text)
            .show_ui(ui, |ui| {
                if ui.selectable_label(host_os.is_none(), "<none>").clicked() {
                    *host_os = None;
                }

                ui.separator();

                if ui
                    .selectable_label(host_os.as_deref() == Some("Linux"), "Linux")
                    .clicked()
                {
                    *host_os = Some("Linux".to_string());
                }
                if ui
                    .selectable_label(host_os.as_deref() == Some("Windows"), "Windows")
                    .clicked()
                {
                    *host_os = Some("Windows".to_string());
                }
            });

        if host_os.is_some()
            && ui
                .button(egui_material_icons::icons::ICON_CLEAR)
                .on_hover_text("Clear OS")
                .clicked()
        {
            *host_os = None;
        }
    });
}

/// Type of host rendering
fn ui_host_type_selector(ui: &mut egui::Ui, host_idx: usize, host: &mut Host) {
    ui.horizontal(|ui| {
        ui.label("Type");
        info_icon(ui, "Defines the role of the host. A server provides services, while a user (client) consumes services. If the host is a server, it must define services. If it is a user, it must define client protocols. If set to <auto>, the role is determined automatically: server if at least one service is defined, otherwise user.");
        let selected_text = host.r#type.as_deref().unwrap_or("<auto>").to_string();

        egui::ComboBox::from_id_salt((host_idx, "host_type"))
            .selected_text(selected_text)
            .show_ui(ui, |ui| {
                if ui
                    .selectable_label(host.r#type.is_none(), "<auto>")
                    .clicked()
                {
                    host.r#type = None;
                }
                if ui
                    .selectable_label(host.r#type.as_deref() == Some("server"), "server")
                    .clicked()
                {
                    host.r#type = Some("server".to_string());
                }
                if ui
                    .selectable_label(host.r#type.as_deref() == Some("user"), "user")
                    .clicked()
                {
                    host.r#type = Some("user".to_string());
                }
            });

        if ui.button(egui_material_icons::icons::ICON_CLEAR).on_hover_text("Clear").clicked() {
            host.r#type = None;
        }
    });
}

/// Client protocols rendering
fn ui_host_client_protocols(ui: &mut egui::Ui, host_idx: usize, host: &mut Host) {
    ui.horizontal(|ui| {
        ui.label("Client protocols");
        info_icon(ui, "Specify what services the host is a client of.");
        let popup_id = ui.make_persistent_id(("client_proto_popup", host_idx));
        let add_btn_resp = ui
            .button(format!("{} Add", egui_material_icons::icons::ICON_ADD))
            .on_hover_text("Add protocol");

        egui::Popup::from_toggle_button_response(&add_btn_resp)
            .id(popup_id)
            .show(|ui| {
                ui.set_min_width(POPUP_MIN_WIDTH);

                let search_id = ui.make_persistent_id(("proto_search", host_idx));
                let mut search_text =
                    ui.data_mut(|d| d.get_temp::<String>(search_id).unwrap_or_default());

                let search_resp =
                    ui.add(egui::TextEdit::singleline(&mut search_text).hint_text("Search..."));

                if ui.memory(|m| m.focused().is_none()) {
                    ui.memory_mut(|m| m.request_focus(search_resp.id));
                }

                ui.data_mut(|d| d.insert_temp(search_id, search_text.clone()));

                ui.separator();

                egui::ScrollArea::vertical()
                    .max_height(POPUP_MAX_HEIGHT)
                    .auto_shrink([true; 2])
                    .show(ui, |ui| {
                        ui.set_width(PANEL_MIN_WIDTH);

                        let filter = search_text.to_lowercase();
                        let mut any_shown = false;

                        for (name, _) in host_services::KNOWN_SERVICES {
                            if (filter.is_empty() || name.to_lowercase().contains(&filter))
                                && !host.client.contains(&name.to_string())
                            {
                                any_shown = true;
                                if ui.selectable_label(false, *name).clicked() {
                                    host.client.push(name.to_string());
                                    ui.data_mut(|d| d.insert_temp(search_id, String::new()));
                                    egui::Popup::close_id(ui.ctx(), popup_id);
                                }
                            }
                        }

                        if !any_shown {
                            ui.label(
                                egui::RichText::new("No available protocols")
                                    .italics()
                                    .weak(),
                            );
                        }
                    });
            });

        let mut proto_to_remove: Option<usize> = None;
        for (p_idx, proto) in host.client.iter().enumerate() {
            let btn_text = format!("{} {}", proto, egui_material_icons::icons::ICON_CLEAR);
            if ui
                .button(btn_text)
                .on_hover_text("Remove protocol")
                .clicked()
            {
                proto_to_remove = Some(p_idx);
            }
        }
        if let Some(idx) = proto_to_remove {
            host.client.remove(idx);
        }
    });
}

/// Determines the best label for a host (Hostname > IP > Default)
fn host_display_name(host: &Host) -> String {
    if let Some(name) = host.hostname.as_deref() {
        if !name.trim().is_empty() {
            return name.to_string();
        }
    }

    if let Some(iface) = host.interfaces.first() {
        if !iface.ip_addr.trim().is_empty() {
            return iface.ip_addr.clone();
        }
    }

    "Unconfigured host".to_string()
}
