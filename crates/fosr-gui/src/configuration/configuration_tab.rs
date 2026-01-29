use crate::shared::config_model::{Configuration, Host, Interface};
use crate::shared::configuration_file::{
    ConfigurationFileState, configuration_file_picker, load_config_file_contents,
};
use crate::shared::ui_utils::{edit_optional_multiline_string, edit_optional_string};
use chrono::NaiveDate;
use eframe::egui;
use egui_extras::DatePickerButton;
use std::collections::HashSet;

/// Scans all interfaces to find the next available IP in 192.168.0.x
fn next_free_ip(used_ips: &HashSet<String>) -> Option<String> {
    for x in 1..=254 {
        let candidate = format!("192.168.0.{x}");
        if !used_ips.contains(&candidate) {
            return Some(candidate);
        }
    }

    None
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

const KNOWN_SERVICES: &[(&str, Option<u16>)] = &[
    ("http", Some(80)),
    ("https", Some(443)),
    ("ssh", Some(22)),
    ("ftp", Some(21)),
    ("smtp", Some(25)),
    ("dns", Some(53)),
];

/// Splits "name:port" into ("name", Some(port))
fn parse_service(s: &str) -> (String, Option<u16>) {
    if let Some((name, port)) = s.split_once(':') {
        if let Ok(p) = port.parse::<u16>() {
            return (name.to_string(), Some(p));
        }
    }
    (s.to_string(), None)
}

/// Joins name and port into "name:port" or just "name"
fn format_service(name: &str, port: Option<u16>) -> String {
    match port {
        Some(p) => format!("{name}:{p}"),
        None => name.to_string(),
    }
}

/**
* Represents the state of the configuration tab.
*/
pub struct ConfigurationTabState {}

impl Default for ConfigurationTabState {
    fn default() -> Self {
        Self {}
    }
}

/// The main tab component
pub fn show_configuration_tab_content(
    ui: &mut egui::Ui,
    _tab_state: &mut ConfigurationTabState,
    file_state: &mut ConfigurationFileState,
) {
    egui::ScrollArea::vertical().show(ui, |ui| {
        // File Selection
        configuration_file_picker(ui, file_state);
        ui.separator();

        ui_parsing_status(ui, file_state);

        // Editor (if model is loaded)
        if let Some(model) = file_state.config_model.as_mut() {
            ui_metadata(ui, model);
            ui.separator();
            ui_hosts_section(ui, model);
            ui.separator();

            // YAML Preview Button
            if ui.button("Export YAML (preview)").clicked() {
                match serde_yaml::to_string(&*model) {
                    Ok(yaml) => {
                        file_state.config_file_content = Some(yaml);
                        file_state.parse_error = None;
                    }
                    Err(e) => {
                        file_state.parse_error = Some(e.to_string());
                    }
                }
            }
        }

        ui_yaml_preview(ui, file_state);
    });
}

/// Status & Feedback
fn ui_parsing_status(ui: &mut egui::Ui, state: &ConfigurationFileState) {
    if state.picked_config_file.is_some() {
        if let Some(err) = &state.parse_error {
            ui.colored_label(egui::Color32::RED, "YAML parsing failed:");
            ui.label(err);
        } else if state.config_model.is_some() {
            ui.colored_label(egui::Color32::GREEN, "YAML parsed successfully ✅");
        } else if state.config_file_content.is_some() {
            ui.colored_label(egui::Color32::YELLOW, "YAML loaded, but not parsed yet.");
        }
        ui.separator();
    }
}

/// Metadata rendering
fn ui_metadata(ui: &mut egui::Ui, model: &mut Configuration) {
    ui.heading("Metadata");
    ui.add_space(6.0);

    // Title (Mandatory)
    ui.horizontal(|ui| {
        ui.label("Title:");
        let title = model.metadata.title.get_or_insert_with(String::new);
        ui.text_edit_singleline(title);
    });

    edit_optional_multiline_string(
        ui,
        "Description (optional):",
        &mut model.metadata.desc,
        "Optional description",
        3,
    );

    edit_optional_string(
        ui,
        "Author (optional):",
        &mut model.metadata.author,
        "Jane Doe",
    );

    // Date Picker
    ui.horizontal(|ui| {
        ui.label("Date (optional):");
        let mut date_val = model
            .metadata
            .date
            .as_deref()
            .and_then(|s| NaiveDate::parse_from_str(s, "%Y/%m/%d").ok())
            .unwrap_or_else(|| NaiveDate::from_ymd_opt(2025, 1, 1).unwrap());

        if ui.add(DatePickerButton::new(&mut date_val)).changed() {
            model.metadata.date = Some(date_val.format("%Y/%m/%d").to_string());
        }

        if ui.button("Clear").clicked() {
            model.metadata.date = None;
        }
    });

    edit_optional_string(
        ui,
        "Version (optional):",
        &mut model.metadata.version,
        "0.1.0",
    );

    // Format (Reserved)
    ui.horizontal(|ui| {
        ui.label("Format:");
        let current = model.metadata.format.unwrap_or(1);
        ui.label(current.to_string())
            .on_hover_text("Reserved for now. Should remain 1.");

        if ui.button("Set to 1").clicked() {
            model.metadata.format = Some(1);
        }
        if ui.button("Clear").clicked() {
            model.metadata.format = None;
        }
    });
}

/// Several host rendering
fn ui_hosts_section(ui: &mut egui::Ui, model: &mut Configuration) {
    ui.heading("Hosts");
    ui.add_space(6.0);

    ui.horizontal(|ui| {
        if ui.button("+ Add host").clicked() {
            model.hosts.push(Host::default());
        }
    });
    ui.add_space(6.0);

    if model.hosts.is_empty() {
        ui.label("No hosts in this configuration.");
        return;
    }

    // Pre-calculate used IPs to avoid borrow checker conflicts
    let mut used_ips = HashSet::new();
    for h in &model.hosts {
        for iface in &h.interfaces {
            used_ips.insert(iface.ip_addr.clone());
        }
    }

    let mut host_to_remove: Option<usize> = None;

    for (idx, host) in model.hosts.iter_mut().enumerate() {
        ui_single_host(ui, idx, host, &used_ips, &mut host_to_remove);
        ui.add_space(6.0);
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
    used_ips: &HashSet<String>,
    remove_request: &mut Option<usize>,
) {
    let host_name = host_display_name(host);
    let header_name = host
        .hostname
        .clone()
        .unwrap_or_else(|| "<no hostname>".to_string());
    let header_type = host.r#type.clone().unwrap_or_else(|| "<auto>".to_string());
    let if_count = host.interfaces.len();

    egui::CollapsingHeader::new(host_name)
        .id_salt(("host", index))
        .default_open(index == 0)
        .show(ui, |ui| {
            // Header Info & Remove Button
            ui.horizontal(|ui| {
                ui.strong(format!(
                    "{header_name} | type: {header_type} | interfaces: {if_count}"
                ));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Remove host").clicked() {
                        *remove_request = Some(index);
                    }
                });
            });

            // Editable Fields
            edit_optional_string(ui, "Hostname (optional):", &mut host.hostname, "host1");
            edit_optional_string(ui, "OS (optional):", &mut host.os, "Linux");

            // Usage DragValue
            ui.horizontal(|ui| {
                ui.label("Usage (optional):");
                let mut usage_val = host.usage.unwrap_or(1.0);
                if ui
                    .add(egui::DragValue::new(&mut usage_val).speed(0.1))
                    .changed()
                {
                    // Avoid saving 1.0 if it's the default
                    host.usage = if (usage_val - 1.0).abs() < f32::EPSILON {
                        None
                    } else {
                        Some(usage_val)
                    };
                }
                if ui.button("Clear").clicked() {
                    host.usage = None;
                }
            });

            // Type Selection
            ui_host_type_selector(ui, index, host);

            // Client Protocols
            ui_host_client_protocols(ui, host);

            ui.separator();

            // Interfaces
            ui_interfaces_section(ui, index, host, used_ips);
        });
}

/// Type of host rendering
fn ui_host_type_selector(ui: &mut egui::Ui, host_idx: usize, host: &mut Host) {
    ui.horizontal(|ui| {
        ui.label("Type (optional):");
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

        if ui.button("Clear").clicked() {
            host.r#type = None;
        }
    });
}

/// Client protocols rendering
fn ui_host_client_protocols(ui: &mut egui::Ui, host: &mut Host) {
    ui.horizontal(|ui| {
        ui.label("Client protocols (optional):");
        let mut buf = if host.client.is_empty() {
            String::new()
        } else {
            host.client.join(",")
        };

        let resp = ui.add(egui::TextEdit::singleline(&mut buf).hint_text("ex: http,https,ssh"));

        if resp.changed() {
            host.client = buf
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }

        if ui.button("Clear").clicked() {
            host.client.clear();
        }
    });
}

/// Interface section rendering
fn ui_interfaces_section(
    ui: &mut egui::Ui,
    host_idx: usize,
    host: &mut Host,
    used_ips: &HashSet<String>,
) {
    ui.horizontal(|ui| {
        ui.label("Interfaces:");
        if ui.button("+ Add interface").clicked() {
            if let Some(ip) = next_free_ip(used_ips) {
                host.interfaces.push(Interface {
                    ip_addr: ip,
                    mac_addr: None,
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

        egui::CollapsingHeader::new(format!("Interface — {ip_label}"))
            .id_salt(("iface", host_idx, if_idx))
            .default_open(if_idx == 0)
            .show(ui, |ui| {
                if ui.button("Remove interface").clicked() {
                    iface_to_remove = Some(if_idx);
                }
                ui.add_space(4.0);

                // IP & MAC
                ui.horizontal(|ui| {
                    ui.label("IP (mandatory):");
                    ui.text_edit_singleline(&mut iface.ip_addr);
                });
                edit_optional_string(
                    ui,
                    "MAC (optional):",
                    &mut iface.mac_addr,
                    "00:14:2A:3F:47:D8",
                );

                // Services
                ui_services_section(ui, if_idx, iface);
            });

        ui.add_space(6.0);
    }

    if let Some(idx) = iface_to_remove {
        host.interfaces.remove(idx);
    }
}

/// Service section rendering
fn ui_services_section(ui: &mut egui::Ui, iface_idx: usize, iface: &mut Interface) {
    let svc_count = iface.services.len();

    egui::CollapsingHeader::new(format!("Services ({svc_count})"))
        .default_open(false)
        .show(ui, |ui| {
            if ui.button("+ Add service").clicked() {
                iface.services.push("http".to_string());
            }
            ui.add_space(4.0);

            let mut svc_to_remove: Option<usize> = None;

            for (svc_idx, svc_raw) in iface.services.iter_mut().enumerate() {
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui_single_service(ui, iface_idx, svc_idx, svc_raw, &mut svc_to_remove);
                });
                ui.add_space(4.0);
            }

            if let Some(idx) = svc_to_remove {
                iface.services.remove(idx);
            }
        });
}

/// Single service rendering
fn ui_single_service(
    ui: &mut egui::Ui,
    iface_idx: usize,
    svc_idx: usize,
    svc_raw: &mut String,
    remove_request: &mut Option<usize>,
) {
    let (mut svc_name, mut svc_port) = parse_service(svc_raw);

    ui.horizontal(|ui| {
        // Name ComboBox
        egui::ComboBox::from_id_salt((iface_idx, svc_idx, "service_name"))
            .selected_text(&svc_name)
            .show_ui(ui, |ui| {
                for (name, default_port) in KNOWN_SERVICES {
                    if ui.selectable_label(&svc_name == name, *name).clicked() {
                        svc_name = name.to_string();
                        svc_port = *default_port;
                    }
                }
            });

        // Port Editor
        ui.label("Port:");
        let mut port_val = svc_port.unwrap_or(0);
        if ui
            .add(
                egui::DragValue::new(&mut port_val)
                    .speed(1)
                    .range(0..=65535),
            )
            .changed()
        {
            svc_port = if port_val == 0 { None } else { Some(port_val) };
        }
        if ui.button("Clear port").clicked() {
            svc_port = None;
        }

        if ui.button("Delete service").clicked() {
            *remove_request = Some(svc_idx);
        }
    });

    *svc_raw = format_service(&svc_name, svc_port);
}

/// Read-only YAML Preview
fn ui_yaml_preview(ui: &mut egui::Ui, state: &mut ConfigurationFileState) {
    if state.picked_config_file.is_none() {
        ui.label("No configuration file selected");
        return;
    }

    if state.config_file_content.is_none() {
        ui.label("Loading configuration file...");
        load_config_file_contents(state);
    } else {
        let content = state.config_file_content.as_ref().unwrap();
        let theme = egui_extras::syntax_highlighting::CodeTheme::from_memory(ui.ctx(), ui.style());

        let mut layout_job = egui_extras::syntax_highlighting::highlight(
            ui.ctx(),
            ui.style(),
            &theme,
            content,
            "yaml",
        );

        layout_job.wrap.max_width = ui.available_width();

        ui.add(egui::Label::new(layout_job).selectable(true));
    }
}
