//! Service editing UI: HTTP, SSH, DNS, etc. with custom port support.

use crate::shared::config::model::Interface;
use crate::shared::constants::network::{PORT_DEFAULT_UNKNOWN, PORT_MAX, PORT_MIN};
use crate::shared::constants::ui::{
    PANEL_MIN_WIDTH, POPUP_MAX_HEIGHT, POPUP_MIN_WIDTH, SPACING_SM, SPACING_XS,
};
use crate::shared::widgets::helpers::info_icon_with_tooltip;
use eframe::egui;

pub const KNOWN_SERVICES: &[(&str, Option<u16>)] = &[
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

/// Look up the default port for a known service name.
///
/// Returns `PORT_DEFAULT_UNKNOWN` (0) if the service is not in KNOWN_SERVICES.
fn default_port_for_service(name: &str) -> u16 {
    KNOWN_SERVICES
        .iter()
        .find(|(n, _)| *n == name)
        .and_then(|(_, p)| *p)
        .unwrap_or(PORT_DEFAULT_UNKNOWN)
}

/// Service section rendering
pub fn ui_services_section(
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
            info_icon_with_tooltip(ui, "The list of available services provided by the host.");
        })
        .body(|ui| {
            let popup_id = ui.make_persistent_id(("svc_popup", host_idx, iface_idx));
            let add_btn_resp = ui
                .button(format!("{} Add", egui_material_icons::icons::ICON_ADD))
                .on_hover_text("Add service");

            egui::Popup::from_toggle_button_response(&add_btn_resp)
                .id(popup_id)
                .show(|ui| {
                    ui.set_min_width(POPUP_MIN_WIDTH);

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
                        .max_height(POPUP_MAX_HEIGHT)
                        .auto_shrink([true; 2])
                        .show(ui, |ui| {
                            ui.set_width(PANEL_MIN_WIDTH);

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

            ui.add_space(SPACING_SM);

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
                ui.add_space(SPACING_XS);
            }

            if let Some(idx) = svc_to_remove {
                iface.services.remove(idx);
            }
        });
}

/// Render a single service row with name, remove button, and optional custom port.
fn ui_single_service(
    ui: &mut egui::Ui,
    host_idx: usize,
    iface_idx: usize,
    svc_idx: usize,
    svc_raw: &mut String,
    remove_request: &mut Option<usize>,
) {
    let (svc_name, mut svc_port) = parse_service(svc_raw);
    let default_port = default_port_for_service(&svc_name);

    // Track whether custom port mode is enabled (persists across frames)
    let custom_port_id = ui.make_persistent_id(("custom_port", host_idx, iface_idx, svc_idx));
    let is_custom_by_default = svc_port.map_or(false, |p| p != default_port);
    let mut custom_port_enabled: bool =
        ui.data_mut(|d| d.get_temp(custom_port_id).unwrap_or(is_custom_by_default));

    ui.horizontal(|ui| {
        // Remove button with service name
        let btn_text = format!("{} {}", svc_name, egui_material_icons::icons::ICON_CLEAR);
        if ui
            .button(btn_text)
            .on_hover_text("Remove service")
            .clicked()
        {
            *remove_request = Some(svc_idx);
        }

        // Custom port toggle
        if ui
            .checkbox(&mut custom_port_enabled, "Custom port")
            .changed()
        {
            svc_port = resolve_port_after_toggle(custom_port_enabled, default_port);
        }

        // Port value editor or default display
        svc_port = render_port_editor(ui, custom_port_enabled, svc_port, default_port);
    });

    // Persist custom port state
    ui.data_mut(|d| d.insert_temp(custom_port_id, custom_port_enabled));

    // Update the service string
    *svc_raw = format_service(&svc_name, svc_port);
}

/// Resolve port value after toggling custom port checkbox.
///
/// When disabling custom port, returns the default (or None if default is 0).
/// When enabling, returns None to be filled by the editor.
fn resolve_port_after_toggle(custom_enabled: bool, default_port: u16) -> Option<u16> {
    if custom_enabled {
        None // Will be set by the DragValue
    } else if default_port == PORT_DEFAULT_UNKNOWN {
        None
    } else {
        Some(default_port)
    }
}

/// Render the port editor: either a DragValue or a read-only default label.
///
/// Returns the selected port value (if any).
fn render_port_editor(
    ui: &mut egui::Ui,
    custom_enabled: bool,
    current_port: Option<u16>,
    default_port: u16,
) -> Option<u16> {
    if custom_enabled {
        let mut port_val = current_port.unwrap_or(default_port);
        if ui
            .add(
                egui::DragValue::new(&mut port_val)
                    .speed(1)
                    .range(PORT_MIN..=PORT_MAX),
            )
            .changed()
        {
            Some(port_val)
        } else {
            Some(port_val) // Return current value even if unchanged
        }
    } else {
        // Show default port as read-only label
        ui.add_enabled(
            false,
            egui::Label::new(egui::RichText::new(format!("(default: {default_port})")).weak()),
        );
        if default_port == PORT_DEFAULT_UNKNOWN {
            None
        } else {
            Some(default_port)
        }
    }
}
