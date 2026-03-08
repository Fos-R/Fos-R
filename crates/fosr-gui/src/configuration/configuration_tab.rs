use crate::shared::config_model::{Configuration, Host, Interface};
use crate::shared::configuration_file::{
    ConfigurationFileState, configuration_file_picker, load_config_file_contents, parse_config_yaml,
};
use crate::shared::ui_utils::{edit_optional_multiline_string, edit_optional_string, info_icon};
use eframe::egui;
use egui::{TextFormat, text::LayoutJob};
use std::collections::HashMap;

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

    ui.add_space(4.0);

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
    ui.label(job).on_hover_text("Mandatory");
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

/// Check MAC format (ex: 00:14:2A:3F:47:D8)
fn is_valid_mac(mac: &str) -> bool {
    let parts: Vec<&str> = mac.split(':').collect();
    if parts.len() != 6 {
        return false;
    }
    parts
        .iter()
        .all(|p| p.len() == 2 && u8::from_str_radix(p, 16).is_ok())
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

/// Function to validate if a host is correct
fn validate_host(
    host: &Host,
    ip_counts: &HashMap<String, usize>,
    mac_counts: &HashMap<String, usize>,
) -> Vec<String> {
    let mut errors = Vec::new();

    if host.interfaces.is_empty() {
        errors.push("Missing interface".to_string());
    }

    for iface in &host.interfaces {
        if iface.ip_addr.parse::<std::net::IpAddr>().is_err() {
            errors.push("Invalid IP format".to_string());
        } else if ip_counts.get(&iface.ip_addr).copied().unwrap_or(0) > 1 {
            errors.push("IP conflict".to_string());
        }

        if let Some(mac) = &iface.mac_addr {
            if !is_valid_mac(mac) {
                errors.push("Invalid MAC format".to_string());
            } else if mac_counts.get(mac).copied().unwrap_or(0) > 1 {
                errors.push("MAC conflict".to_string());
            }
        }
    }

    if host.r#type.as_deref() == Some("server") {
        let has_service = host.interfaces.iter().any(|i| !i.services.is_empty());
        if !has_service {
            errors.push("Server missing service".to_string());
        }
    }

    if host.r#type.as_deref() == Some("user") {
        if host.client.is_empty() {
            errors.push("Client missing protocols".to_string());
        }
        let has_service = host.interfaces.iter().any(|i| !i.services.is_empty());
        if has_service {
            errors.push("User host should not have services (use type: server)".to_string());
        }
    }

    errors.dedup();
    errors
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
pub struct ConfigurationTabState {
    pub is_code_mode: bool,
}

impl Default for ConfigurationTabState {
    fn default() -> Self {
        Self {
            is_code_mode: false,
        }
    }
}

/// The main tab component
pub fn show_configuration_tab_content(
    ui: &mut egui::Ui,
    tab_state: &mut ConfigurationTabState,
    file_state: &mut ConfigurationFileState,
) {
    // Eagerly load config file contents when a file is selected
    load_config_file_contents(file_state);

    egui::ScrollArea::vertical().show(ui, |ui| {
        // File Selection
        configuration_file_picker(ui, tab_state, file_state);

        ui_parsing_status(ui, file_state);

        if file_state.config_chosen {
            ui.separator();

            if !tab_state.is_code_mode {
                // Visual mode
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
            } else {
                ui_yaml_editor(ui, file_state);
            }
        }
    });
}

/// Status & Feedback
fn ui_parsing_status(ui: &mut egui::Ui, state: &ConfigurationFileState) {
    if state.picked_config_file.is_some() {
        if let Some(err) = &state.parse_error {
            ui.colored_label(egui::Color32::RED, "YAML parsing failed:");
            ui.label(err);
        } else if state.config_model.is_some() {
            ui.colored_label(egui::Color32::GREEN, "YAML parsed successfully");
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
        "Description",
        &mut model.metadata.desc,
        "Optional description",
        3,
    );

    edit_optional_string(ui, "Author", &mut model.metadata.author, "Jane Doe");

    edit_optional_string(ui, "Version", &mut model.metadata.version, "0.1.0");
}

/// Several host rendering
fn ui_hosts_section(ui: &mut egui::Ui, model: &mut Configuration) {
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
    let errors = validate_host(host, ip_counts, mac_counts);

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
                    ui.colored_label(egui::Color32::RED, label_text)
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
                info_icon(ui, "Optional (default value: 1.0). The usage intensity of the host. 1 is the baseline, < 1 means less usage than usual, and > 1 means higher usage");
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
            ui_interfaces_section(ui, index, host, ip_counts, mac_counts);
        });
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
    });

    ui.horizontal_wrapped(|ui| {
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

        let popup_id = ui.make_persistent_id(("client_proto_popup", host_idx));
        let add_btn_resp = ui
            .button(format!("{} Add", egui_material_icons::icons::ICON_ADD))
            .on_hover_text("Add protocol");

        egui::Popup::from_toggle_button_response(&add_btn_resp)
            .id(popup_id)
            .show(|ui| {
                ui.set_min_width(180.0);

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
                    .max_height(200.0)
                    .auto_shrink([true; 2])
                    .show(ui, |ui| {
                        let desired_content_width = 250.0;
                        ui.set_width(desired_content_width);

                        let filter = search_text.to_lowercase();
                        let mut any_shown = false;

                        for (name, _) in KNOWN_SERVICES {
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
    let id = ui.make_persistent_id(("services", host_idx, iface_idx));

    egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), id, false)
        .show_header(ui, |ui| {
            ui.label(format!("Services ({svc_count})"));
            info_icon(ui, "The list of available services provided by the host.");
        })
        .body(|ui| {
            let popup_id = ui.make_persistent_id(("svc_popup", host_idx, iface_idx));
            let add_btn_resp = ui
                .button(format!("{} Add", egui_material_icons::icons::ICON_ADD))
                .on_hover_text("Add service");

            egui::Popup::from_toggle_button_response(&add_btn_resp)
                .id(popup_id)
                .show(|ui| {
                    ui.set_min_width(180.0);

                    let search_id = ui.make_persistent_id(("svc_search", host_idx, iface_idx));
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
                        .max_height(200.0)
                        .auto_shrink([true; 2])
                        .show(ui, |ui| {
                            ui.set_width(250.0);

                            let filter = search_text.to_lowercase();
                            let mut any_shown = false;

                            for (name, default_port) in KNOWN_SERVICES {
                                let already_present = iface.services.iter().any(|s| {
                                    let (sname, _) = parse_service(s);
                                    &sname == name
                                });

                                if (filter.is_empty() || name.to_lowercase().contains(&filter))
                                    && !already_present
                                {
                                    any_shown = true;
                                    if ui.selectable_label(false, *name).clicked() {
                                        iface.services.push(format_service(name, *default_port));
                                        ui.data_mut(|d| d.insert_temp(search_id, String::new()));
                                        egui::Popup::close_id(ui.ctx(), popup_id);
                                    }
                                }
                            }

                            if !any_shown {
                                ui.label(
                                    egui::RichText::new("No available services")
                                        .italics()
                                        .weak(),
                                );
                            }
                        });
                });

            ui.add_space(4.0);

            let mut svc_to_remove: Option<usize> = None;

            for (svc_idx, svc_raw) in iface.services.iter_mut().enumerate() {
                ui_single_service(
                    ui,
                    host_idx,
                    iface_idx,
                    svc_idx,
                    svc_raw,
                    &mut svc_to_remove,
                );
                ui.add_space(2.0);
            }

            if let Some(idx) = svc_to_remove {
                iface.services.remove(idx);
            }
        });
}

/// Single service rendering
fn ui_single_service(
    ui: &mut egui::Ui,
    host_idx: usize,
    iface_idx: usize,
    svc_idx: usize,
    svc_raw: &mut String,
    remove_request: &mut Option<usize>,
) {
    let (svc_name, mut svc_port) = parse_service(svc_raw);

    let default_port = KNOWN_SERVICES
        .iter()
        .find(|(n, _)| *n == svc_name)
        .and_then(|(_, p)| *p)
        .unwrap_or(0);

    let custom_port_id = ui.make_persistent_id(("custom_port", host_idx, iface_idx, svc_idx));
    let mut custom_port_enabled: bool =
        ui.data_mut(|d| d.get_temp(custom_port_id).unwrap_or(false));

    ui.horizontal(|ui| {
        let btn_text = format!("{} {}", svc_name, egui_material_icons::icons::ICON_CLEAR);
        if ui
            .button(btn_text)
            .on_hover_text("Remove service")
            .clicked()
        {
            *remove_request = Some(svc_idx);
        }

        if ui
            .checkbox(&mut custom_port_enabled, "Custom port")
            .changed()
        {
            if !custom_port_enabled {
                svc_port = if default_port == 0 {
                    None
                } else {
                    Some(default_port)
                };
            }
        }

        if custom_port_enabled {
            let mut port_val = svc_port.unwrap_or(default_port);
            if ui
                .add(
                    egui::DragValue::new(&mut port_val)
                        .speed(1)
                        .range(1..=65535),
                )
                .changed()
            {
                svc_port = Some(port_val);
            }
        } else {
            ui.add_enabled(
                false,
                egui::Label::new(egui::RichText::new(format!("(default: {default_port})")).weak()),
            );
            svc_port = if default_port == 0 {
                None
            } else {
                Some(default_port)
            };
        }
    });

    ui.data_mut(|d| d.insert_temp(custom_port_id, custom_port_enabled));

    *svc_raw = format_service(&svc_name, svc_port);
}

fn parse_error_lines(err: &str) -> Vec<usize> {
    let mut found = Vec::new();
    let mut search = err;
    while let Some(pos) = search.find("line ") {
        let rest = &search[pos + 5..];
        let num: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if let Ok(n) = num.parse::<usize>() {
            if !found.contains(&n) {
                found.push(n);
            }
        }
        search = &search[pos + 5..];
    }
    found
}

/// Editable YAML Editor
fn ui_yaml_editor(ui: &mut egui::Ui, state: &mut ConfigurationFileState) {
    if state.config_file_content.is_none() {
        ui.label("No configuration file selected.");
        return;
    }

    let error_lines: Vec<usize> = if let Some(err) = &state.parse_error {
        ui.colored_label(
            egui::Color32::RED,
            format!(
                "{} YAML parsing failed",
                egui_material_icons::icons::ICON_WARNING
            ),
        );
        ui.colored_label(egui::Color32::RED, err);
        ui.separator();
        parse_error_lines(err)
    } else {
        Vec::new()
    };

    let mut content = state.config_file_content.clone().unwrap();
    let line_count = content.lines().count().max(1);

    let theme = egui_extras::syntax_highlighting::CodeTheme::from_memory(ui.ctx(), ui.style());
    let font_id = egui::TextStyle::Monospace.resolve(ui.style());
    let line_height = ui.fonts_mut(|f| f.row_height(&font_id));
    let digit_width = ui.fonts_mut(|f| f.glyph_width(&font_id, '0'));
    let digits = line_count.to_string().len();
    let icon_col_width = 20.0;
    let gutter_width = digit_width * digits as f32 + 6.0 + icon_col_width;

    let gutter_color = ui.visuals().weak_text_color();
    let error_color = egui::Color32::from_rgb(220, 50, 50);
    let gutter_bg = ui.visuals().extreme_bg_color;

    let scroll_offset_id = ui.make_persistent_id("yaml_editor_scroll_y");
    let scroll_y: f32 = ui.data(|d| d.get_temp(scroll_offset_id).unwrap_or(0.0));

    let mut editor_changed = false;
    let mut new_scroll_y = scroll_y;

    ui.horizontal_top(|ui| {
        let available_height = ui.available_height();

        let (gutter_rect, _) = ui.allocate_exact_size(
            egui::vec2(gutter_width, available_height),
            egui::Sense::hover(),
        );

        ui.painter().rect_filled(gutter_rect, 0.0, gutter_bg);

        let first_visible = (scroll_y / line_height).floor() as usize;
        let visible_count = (available_height / line_height).ceil() as usize + 2;

        for i in first_visible..(first_visible + visible_count).min(line_count) {
            let line_num = i + 1;
            let y_offset = i as f32 * line_height - scroll_y;
            let y = gutter_rect.top() + y_offset;

            if y > gutter_rect.bottom() {
                break;
            }

            let is_error = error_lines.contains(&line_num);
            let num_color = if is_error { error_color } else { gutter_color };

            let num_str = format!("{:>width$}", line_num, width = digits);
            let num_col_right = gutter_rect.left() + digit_width * digits as f32 + 4.0;
            ui.painter().text(
                egui::pos2(gutter_rect.left() + 2.0, y),
                egui::Align2::LEFT_TOP,
                num_str,
                font_id.clone(),
                num_color,
            );

            if is_error {
                let icon_rect = egui::Rect::from_min_size(
                    egui::pos2(num_col_right, y),
                    egui::vec2(icon_col_width, line_height),
                );
                ui.scope_builder(egui::UiBuilder::new().max_rect(icon_rect), |ui| {
                    ui.colored_label(error_color, egui_material_icons::icons::ICON_WARNING);
                });
            }
        }

        let mut layouter = |ui: &egui::Ui, text: &dyn egui::TextBuffer, wrap_width: f32| {
            let mut layout_job = egui_extras::syntax_highlighting::highlight(
                ui.ctx(),
                ui.style(),
                &theme,
                text.as_str(),
                "yaml",
            );
            layout_job.wrap.max_width = wrap_width;
            ui.fonts_mut(|f| f.layout_job(layout_job))
        };

        let scroll_out = egui::ScrollArea::vertical()
            .id_salt("yaml_scroll_area")
            .show(ui, |ui| {
                ui.add(
                    egui::TextEdit::multiline(&mut content)
                        .font(egui::TextStyle::Monospace)
                        .code_editor()
                        .desired_rows(20)
                        .lock_focus(true)
                        .desired_width(f32::INFINITY)
                        .layouter(&mut layouter),
                )
            });

        new_scroll_y = scroll_out.state.offset.y;
        editor_changed = scroll_out.inner.changed();
    });

    ui.data_mut(|d| d.insert_temp(scroll_offset_id, new_scroll_y));

    if editor_changed {
        state.config_file_content = Some(content);
        parse_config_yaml(state);
    }
}
