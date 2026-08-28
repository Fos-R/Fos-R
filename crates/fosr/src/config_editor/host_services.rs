//! Service editing UI: HTTP, SSH, DNS, etc. with custom port support.

use crate::shared::constants::network::{PORT_MAX, PORT_MIN, PORT_UNSPECIFIED};
use crate::shared::constants::ui::{MULTI_SELECT_PICKER_WIDTH, SPACING_XS};
use crate::shared::widgets::helpers::info_icon_with_tooltip;
use crate::shared::widgets::multi_select_picker::multi_select_picker;
use eframe::egui;
use fosr_lib::network::InterfaceYaml;
use fosr_lib::structs::{L7Proto,Port};
use std::str::FromStr;

/// Splits "name:port" into ("name", Some(port))
fn parse_service(s: &str) -> (String, Option<u16>) {
    if let Some((name, port)) = s.split_once(':')
        && let Ok(p) = port.parse::<u16>()
    {
        return (name.to_string(), Some(p));
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

/// Look up the default port for a known service name via L7Proto.
fn default_port_for_service(name: &str) -> u16 {
    match L7Proto::from_str(name)
        .map(|p| p.get_default_dst_port()) {
        Ok(Some(Port::Fixed(p))) => p,
        _ => PORT_UNSPECIFIED,
        }
}

/// Service section rendering.
pub fn render_services_section(
    ui: &mut egui::Ui,
    host_idx: usize,
    interface_idx: usize,
    interface: &mut InterfaceYaml,
) {
    let service_count = interface.services.as_ref().map_or(0, |s| s.len());

    // Picker in a horizontal line: label + info icon + select
    let service_names = L7Proto::all_names();
    let service_name_refs: Vec<&str> = service_names.iter().map(|s| s.as_str()).collect();
    let mut selected_names: Vec<String> = interface
        .services
        .as_ref()
        .map(|s| s.iter().map(|svc| parse_service(svc).0).collect())
        .unwrap_or_default();

    ui.horizontal(|ui| {
        let header_label = format!("Services ({service_count})");
        if service_count > 0 {
            let tooltip: Vec<String> = interface
                .services
                .as_ref()
                .map(|s| {
                    s.iter()
                        .map(|svc| {
                            let (name, port) = parse_service(svc);
                            match port {
                                Some(p) => format!("{name}:{p}"),
                                None => name,
                            }
                        })
                        .collect()
                })
                .unwrap_or_default();
            ui.label(&header_label).on_hover_text(tooltip.join("\n"));
        } else {
            ui.label(header_label);
        }
        info_icon_with_tooltip(
            ui,
            "The list of services provided by the host on this interface.",
        );

        let picker_id = ui.make_persistent_id(("service_picker", host_idx, interface_idx));
        multi_select_picker(
            ui,
            picker_id,
            &service_name_refs,
            &mut selected_names,
            MULTI_SELECT_PICKER_WIDTH,
        );
    });

    // Sync picker selection back to interface services
    let services = interface.services.get_or_insert_with(Vec::new);
    sync_services(services, &selected_names);

    // Collapsible section with port customization
    if !services.is_empty() {
        let id = ui.make_persistent_id(("services_ports", host_idx, interface_idx));
        egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), id, false)
            .show_header(ui, |ui| {
                ui.weak("Custom ports");
            })
            .body(|ui| {
                for service_raw in services.iter_mut() {
                    render_service_row(ui, host_idx, interface_idx, service_raw);
                    ui.add_space(SPACING_XS);
                }
            });
    }
}

/// Sync the picker's name-based selection with the interface's "name:port" services.
///
/// - Adds new services with their default port.
/// - Removes deselected services.
/// - Preserves custom ports for services that remain selected.
fn sync_services(services: &mut Vec<String>, selected_names: &[String]) {
    // Remove services not in the picker selection
    services.retain(|s| {
        let name = parse_service(s).0;
        selected_names.iter().any(|n| n == &name)
    });

    // Add newly selected services that aren't in the list yet
    for name in selected_names {
        let exists = services.iter().any(|s| parse_service(s).0 == *name);
        if !exists {
            let port = default_port_for_service(name);
            services.push(format_service(name, Some(port)));
        }
    }
}

/// Render a single service row with name label and optional custom port editor.
fn render_service_row(
    ui: &mut egui::Ui,
    host_idx: usize,
    interface_idx: usize,
    service_raw: &mut String,
) {
    let (service_name, mut service_port) = parse_service(service_raw);
    let default_port = default_port_for_service(&service_name);

    // Track whether custom port mode is enabled (persists across frames)
    let custom_port_id =
        ui.make_persistent_id(("custom_port", host_idx, interface_idx, &*service_raw));
    let is_custom_by_default = service_port.is_some_and(|p| p != default_port);
    let mut custom_port_enabled: bool =
        ui.data_mut(|d| d.get_temp(custom_port_id).unwrap_or(is_custom_by_default));

    ui.horizontal(|ui| {
        // Service name as a label
        ui.strong(&service_name);

        // Custom port toggle
        if ui
            .checkbox(&mut custom_port_enabled, "Custom port")
            .changed()
        {
            service_port = resolve_port_after_toggle(custom_port_enabled, default_port);
        }

        // Port value editor or default display
        service_port = render_port_editor(ui, custom_port_enabled, service_port, default_port);
    });

    // Persist custom port state
    ui.data_mut(|d| d.insert_temp(custom_port_id, custom_port_enabled));

    // Update the service string
    *service_raw = format_service(&service_name, service_port);
}

/// Resolve port value after toggling custom port checkbox.
fn resolve_port_after_toggle(custom_enabled: bool, default_port: u16) -> Option<u16> {
    if custom_enabled || default_port == PORT_UNSPECIFIED {
        None
    } else {
        Some(default_port)
    }
}

/// Render the port editor: either a DragValue or a read-only default label.
fn render_port_editor(
    ui: &mut egui::Ui,
    custom_enabled: bool,
    current_port: Option<u16>,
    default_port: u16,
) -> Option<u16> {
    if custom_enabled {
        let mut port_val = current_port.unwrap_or(default_port);
        ui.add(
            egui::DragValue::new(&mut port_val)
                .speed(1)
                .range(PORT_MIN..=PORT_MAX),
        );
        Some(port_val)
    } else {
        ui.add(egui::Label::new(
            egui::RichText::new(format!("(default: {default_port})")).weak(),
        ));
        if default_port == PORT_UNSPECIFIED {
            None
        } else {
            Some(default_port)
        }
    }
}
