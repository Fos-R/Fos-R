use crate::shared::config_model::{Configuration, Host, Interface};
use crate::shared::configuration_file::{
    ConfigurationFileState, configuration_file_picker, load_config_file_contents,
};
use crate::shared::ui_utils::{edit_optional_multiline_string, edit_optional_string, info_icon};
use eframe::egui;
use egui::{TextFormat, text::LayoutJob};
use std::collections::HashMap;

// Helper for required label with red *
fn required_label(ui: &mut egui::Ui, text: &str) {
    let mut job = LayoutJob::default();

    job.append(
        text,
        0.0,
        TextFormat {
            color: ui.visuals().text_color(),
            ..Default::default()
        },
    );

    job.append(
        "*",
        0.0,
        TextFormat {
            color: egui::Color32::RED,
            ..Default::default()
        },
    );

    job.append(
        ":",
        0.0,
        TextFormat {
            color: ui.visuals().text_color(),
            ..Default::default()
        },
    );

    ui.label(job);
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

/// Represents the state of the configuration tab.
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
    // Eagerly load config file contents when a file is selected
    load_config_file_contents(file_state);

    egui::ScrollArea::vertical().show(ui, |ui| {
        // File Selection
        configuration_file_picker(ui, file_state);
        ui.separator();

        ui_parsing_status(ui, file_state);

        // Editor (if model is loaded)
        if let Some(model) = file_state.config_model.as_mut() {
            ui_hosts_section(ui, model);
            ui.separator();
            ui_metadata(ui, model);
            ui.separator();
        }

        // Auto-sync model edits back to YAML so other tabs see the changes
        if let Some(model) = &file_state.config_model {
            match serde_yaml::to_string(model) {
                Ok(yaml) => {
                    file_state.config_file_content = Some(yaml);
                    file_state.parse_error = None;
                }
                Err(e) => {
                    file_state.parse_error = Some(e.to_string());
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

    // Title
    ui.horizontal(|ui| {
        required_label(ui, "Title");
        let title = model.metadata.title.get_or_insert_with(String::new);
        ui.text_edit_singleline(title);
    });

    edit_optional_multiline_string(
        ui,
        "Description:",
        &mut model.metadata.desc,
        "Optional description",
        3,
    );

    edit_optional_string(ui, "Author:", &mut model.metadata.author, "Jane Doe");

    edit_optional_string(ui, "Version:", &mut model.metadata.version, "0.1.0");
}

/// Several host rendering
fn ui_hosts_section(ui: &mut egui::Ui, model: &mut Configuration) {
    ui.heading("Hosts");
    ui.add_space(6.0);

    ui.horizontal(|ui| {
        if ui.button(egui_material_icons::icons::ICON_ADD).on_hover_text("Add host").clicked() {
            model.hosts.push(Host::default());
        }
    });
    ui.add_space(6.0);

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
    ip_counts: &HashMap<String, usize>,
    mac_counts: &HashMap<String, usize>,
    remove_request: &mut Option<usize>,
) {
    let host_name = host_display_name(host);
    let header_name = host
        .hostname
        .clone()
        .unwrap_or_else(|| "<no hostname>".to_string());
    let header_type = host.r#type.clone().unwrap_or_else(|| "<auto>".to_string());
    let if_count = host.interfaces.len();

    let id = ui.make_persistent_id(("host", index));
    egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), id, index == 0)
        .show_header(ui, |ui| {
            ui.label(host_name);

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button(egui_material_icons::icons::ICON_DELETE).on_hover_text("Remove host").clicked() {
                    *remove_request = Some(index);
                }
            });
        })
        .body(|ui| {
            ui.horizontal(|ui| {
                ui.strong(format!(
                    "{header_name} | type: {header_type} | interfaces: {if_count}"
                ));
            });

            ui_host_os_selector(ui, index, &mut host.os);
            edit_optional_string(ui, "Hostname:", &mut host.hostname, "host1");

            ui.horizontal(|ui| {
                ui.label("Usage:");
                info_icon(ui, "How much is the host active");
                let mut usage_val = host.usage.unwrap_or(1.0);
                if ui
                    .add(egui::DragValue::new(&mut usage_val).speed(0.1))
                    .changed()
                {
                    host.usage = if (usage_val - 1.0).abs() < f32::EPSILON {
                        None
                    } else {
                        Some(usage_val)
                    };
                }
                if ui.button(egui_material_icons::icons::ICON_CLEAR).on_hover_text("Clear").clicked() {
                    host.usage = None;
                }
            });

            ui_host_type_selector(ui, index, host);
            ui_host_client_protocols(ui, host);
            ui.separator();
            ui_interfaces_section(ui, index, host, ip_counts, mac_counts);
        });
}

/// Dropdown selector for the Operating System
fn ui_host_os_selector(ui: &mut egui::Ui, host_idx: usize, host_os: &mut Option<String>) {
    ui.horizontal(|ui| {
        ui.label("OS:");

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

        if host_os.is_some() && ui.button(egui_material_icons::icons::ICON_CLEAR).on_hover_text("Clear OS").clicked() {
            *host_os = None;
        }
    });
}

/// Type of host rendering
fn ui_host_type_selector(ui: &mut egui::Ui, host_idx: usize, host: &mut Host) {
    ui.horizontal(|ui| {
        ui.label("Type:");
        info_icon(ui, "If the host is a server then it will provide services, if it is a client it will use a service. If the host is a server it needs services, if it is a client it needs clients protocols.");
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
fn ui_host_client_protocols(ui: &mut egui::Ui, host: &mut Host) {
    ui.horizontal(|ui| {
        ui.label("Client protocols:");
        info_icon(ui, "Protocols the host is going to use from other servers");
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

        if ui.button(egui_material_icons::icons::ICON_CLEAR).on_hover_text("Clear").clicked() {
            host.client.clear();
        }
    });
}

/// Interface section rendering
fn ui_interfaces_section(
    ui: &mut egui::Ui,
    host_idx: usize,
    host: &mut Host,
    ip_counts: &HashMap<String, usize>,
    mac_counts: &HashMap<String, usize>,
) {
    ui.horizontal(|ui| {
        ui.label("Interfaces:");
        if ui.button(egui_material_icons::icons::ICON_ADD).on_hover_text("Add interface").clicked() {
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
                    if ui.button(egui_material_icons::icons::ICON_DELETE).on_hover_text("Remove interface").clicked() {
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
                edit_optional_string(ui, "MAC:", &mut iface.mac_addr, "00:14:2A:3F:47:D8");
                if let Some(mac) = &iface.mac_addr {
                    if mac_counts.get(mac).copied().unwrap_or(0) > 1 {
                        ui.colored_label(egui::Color32::RED, "MAC already in use");
                    }
                }
                ui_services_section(ui, if_idx, host_idx, iface);
            });
        ui.add_space(6.0);
    }

    if let Some(idx) = iface_to_remove {
        host.interfaces.remove(idx);
    }
}

/// Service section rendering
fn ui_services_section(
    ui: &mut egui::Ui,
    host_idx: usize,
    iface_idx: usize,
    iface: &mut Interface,
) {
    let svc_count = iface.services.len();
    // let id = ui.make_persistent_id(("services", iface_idx));
    let id = ui.make_persistent_id(("services", host_idx, iface_idx));

    egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), id, false)
        .show_header(ui, |ui| {
            ui.label(format!("Services ({svc_count})"));
        })
        .body(|ui| {
            if ui.button(egui_material_icons::icons::ICON_ADD).on_hover_text("Add service").clicked() {
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
        if ui.button(egui_material_icons::icons::ICON_CLEAR).on_hover_text("Clear port").clicked() {
            svc_port = None;
        }

        if ui.button(egui_material_icons::icons::ICON_DELETE).on_hover_text("Delete service").clicked() {
            *remove_request = Some(svc_idx);
        }
    });

    *svc_raw = format_service(&svc_name, svc_port);
}

/// Read-only YAML Preview
fn ui_yaml_preview(ui: &mut egui::Ui, state: &mut ConfigurationFileState) {
    if state.config_file_content.is_none() {
        ui.label("No configuration file selected");
        return;
    }
    let content = state.config_file_content.as_ref().unwrap();
    let theme = egui_extras::syntax_highlighting::CodeTheme::from_memory(ui.ctx(), ui.style());

    let mut layout_job =
        egui_extras::syntax_highlighting::highlight(ui.ctx(), ui.style(), &theme, content, "yaml");

    layout_job.wrap.max_width = ui.available_width();

    ui.add(egui::Label::new(layout_job).selectable(true));
}
