use crate::shared::config_model::Host;
use crate::shared::configuration_file::{
    ConfigurationFileState, configuration_file_picker, load_config_file_contents,
};
use crate::shared::ui_utils::{edit_optional_multiline_string, edit_optional_string};
use chrono::NaiveDate;
use eframe::egui;
use egui_extras::DatePickerButton;

/**
 * Represents the state of the configuration tab.
 */
pub struct ConfigurationTabState {}

impl Default for ConfigurationTabState {
    fn default() -> Self {
        Self {}
    }
}

pub fn show_configuration_tab_content(
    ui: &mut egui::Ui,
    _configuration_tab_state: &mut ConfigurationTabState,
    configuration_file_state: &mut ConfigurationFileState,
) {
    // Config file picker
    configuration_file_picker(ui, configuration_file_state);

    ui.separator();

    // --- Parsing status ---
    if configuration_file_state.picked_config_file.is_some() {
        if let Some(err) = &configuration_file_state.parse_error {
            ui.colored_label(egui::Color32::RED, "YAML parsing failed:");
            ui.label(err);
        } else if configuration_file_state.config_model.is_some() {
            ui.colored_label(egui::Color32::GREEN, "YAML parsed successfully ✅");
        } else if configuration_file_state.config_file_content.is_some() {
            // Content loaded but model not set -> should not happen often, but safe
            ui.colored_label(egui::Color32::YELLOW, "YAML loaded, but not parsed yet.");
        }
        ui.separator();
    }
    if let Some(model) = configuration_file_state.config_model.as_mut() {
        ui.heading("Metadata");
        ui.add_space(6.0);

        // --- title (mandatory in spec, but keep Option<String> for editing) ---
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

        ui.horizontal(|ui| {
            ui.label("Date (optional):");

            let mut date_val = model
                .metadata
                .date
                .as_deref()
                .and_then(|s| NaiveDate::parse_from_str(s, "%Y/%m/%d").ok())
                .unwrap_or_else(|| NaiveDate::from_ymd_opt(2025, 1, 1).unwrap());

            let resp = ui.add(DatePickerButton::new(&mut date_val));

            if resp.changed() {
                model.metadata.date = Some(date_val.format("%Y/%m/%d").to_string());
            }

            if ui.button("Clear").clicked() {
                model.metadata.date = None;
            }
        });

        edit_optional_string(
            ui,
            "Version (optional):",
            &mut model.metadata.author,
            "0.1.0",
        );

        // --- format (reserved) ---
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

        ui.separator();

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
        } else {
            let mut host_to_remove: Option<usize> = None;
            for (host_idx, host) in model.hosts.iter_mut().enumerate() {
                let hostname_for_header = host
                    .hostname
                    .clone()
                    .unwrap_or_else(|| "<no hostname>".to_string());
                let host_type_for_header =
                    host.r#type.clone().unwrap_or_else(|| "<auto>".to_string());
                let if_count = host.interfaces.len();

                // let header = format!(
                //     "Host #{host_idx}: {hostname}  |  type: {host_type}  |  interfaces: {if_count}"
                // );
                //
                // egui::CollapsingHeader::new(header)
                //     .default_open(host_idx == 0) // optionnel: ouvre le premier host par défaut
                //     .show(ui, |ui| {
                egui::CollapsingHeader::new(format!("Host #{host_idx}"))
                    .default_open(host_idx == 0)
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.strong(format!(
                                "{hostname_for_header}  |  type: {host_type_for_header}  |  interfaces: {if_count}"
                            ));
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if ui.button("Remove host").clicked() {
                                        host_to_remove = Some(host_idx);
                                    }
                                },
                            );
                        });
                        // --- Editable host fields ---

                        // Hostname (optional)
                        edit_optional_string(
                            ui,
                            "Hostname (optional):",
                            &mut host.hostname,
                            "host1",
                        );

                        // OS (optional, default is Linux)
                        edit_optional_string(ui, "OS (optional):", &mut host.os, "Linux");

                        // Usage (optional, default is 1.0)
                        ui.horizontal(|ui| {
                            ui.label("Usage (optional):");

                            let mut usage_val = host.usage.unwrap_or(1.0);
                            let resp = ui.add(egui::DragValue::new(&mut usage_val).speed(0.1));

                            if resp.changed() {
                                // If equals default, keep None to avoid polluting YAML
                                if (usage_val - 1.0).abs() < f32::EPSILON {
                                    host.usage = None;
                                } else {
                                    host.usage = Some(usage_val);
                                }
                            }

                            if ui.button("Clear").clicked() {
                                host.usage = None;
                            }
                        });

                        // Type (optional, auto if None)
                        ui.horizontal(|ui| {
                            ui.label("Type (optional):");

                            let selected_text =
                                host.r#type.as_deref().unwrap_or("<auto>").to_string();

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
                                        .selectable_label(
                                            host.r#type.as_deref() == Some("server"),
                                            "server",
                                        )
                                        .clicked()
                                    {
                                        host.r#type = Some("server".to_string());
                                    }
                                    if ui
                                        .selectable_label(
                                            host.r#type.as_deref() == Some("user"),
                                            "user",
                                        )
                                        .clicked()
                                    {
                                        host.r#type = Some("user".to_string());
                                    }
                                });

                            if ui.button("Clear").clicked() {
                                host.r#type = None;
                            }
                        });

                        // Client protocols (optional list)
                        // For now: comma-separated editor
                        ui.horizontal(|ui| {
                            ui.label("Client protocols (optional):");

                            let mut buf = if host.client.is_empty() {
                                String::new()
                            } else {
                                host.client.join(",")
                            };

                            let resp = ui.add(
                                egui::TextEdit::singleline(&mut buf)
                                    .hint_text("ex: http,https,ssh"),
                            );

                            if resp.changed() {
                                host.client = buf
                                    .split(',')
                                    .map(|s| s.trim())
                                    .filter(|s| !s.is_empty())
                                    .map(|s| s.to_string())
                                    .collect();
                            }

                            if ui.button("Clear").clicked() {
                                host.client.clear();
                            }
                        });

                        ui.separator();
                        ui.label("Interfaces:");

                        if host.interfaces.is_empty() {
                            ui.label("No interfaces.");
                        } else {
                            for (if_idx, iface) in host.interfaces.iter().enumerate() {
                                egui::CollapsingHeader::new(format!(
                                    "Interface #{if_idx} — {}",
                                    iface.ip_addr
                                ))
                                .default_open(if_idx == 0)
                                .show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        ui.label("IP:");
                                        ui.monospace(&iface.ip_addr);
                                    });

                                    ui.horizontal(|ui| {
                                        ui.label("MAC:");
                                        ui.monospace(iface.mac_addr.as_deref().unwrap_or("<none>"));
                                    });

                                    let svc_count = iface.services.len();
                                    egui::CollapsingHeader::new(format!("Services ({svc_count})"))
                                        .default_open(false)
                                        .show(ui, |ui| {
                                            if iface.services.is_empty() {
                                                ui.monospace("<none>");
                                            } else {
                                                egui::ScrollArea::vertical().max_height(80.0).show(
                                                    ui,
                                                    |ui| {
                                                        for svc in &iface.services {
                                                            ui.monospace(format!("- {svc}"));
                                                        }
                                                    },
                                                );
                                            }
                                        });
                                });
                            }
                        }
                    });

                ui.add_space(6.0);
            }
            if let Some(idx) = host_to_remove {
                model.hosts.remove(idx);
            }
        }
        ui.separator();
        if ui.button("Export YAML (preview)").clicked() {
            match serde_yaml::to_string(&*model) {
                Ok(yaml) => {
                    configuration_file_state.config_file_content = Some(yaml);
                    configuration_file_state.parse_error = None;
                }
                Err(e) => {
                    configuration_file_state.parse_error = Some(e.to_string());
                }
            }
        }
    }

    // Config file editor
    if configuration_file_state.picked_config_file.is_none() {
        ui.label("No configuration file selected");
    } else {
        if configuration_file_state.config_file_content.is_none() {
            ui.label("Loading configuration file...");
            load_config_file_contents(configuration_file_state);
        } else {
            let content = configuration_file_state
                .config_file_content
                .as_ref()
                .unwrap();
            let theme =
                egui_extras::syntax_highlighting::CodeTheme::from_memory(ui.ctx(), ui.style());
            let language = "yaml";

            let mut layout_job = egui_extras::syntax_highlighting::highlight(
                ui.ctx(),
                ui.style(),
                &theme,
                content,
                language,
            );
            layout_job.wrap.max_width = ui.available_width();
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.add(
                    egui::Label::new(layout_job).selectable(true), // Allows the user to copy the code even if they can't edit it
                );
            });

            // Use this if you want a code editor instead:

            // let mut layouter = |ui: &egui::Ui, buf: &dyn egui::TextBuffer, wrap_width: f32| {
            //     let mut layout_job = egui_extras::syntax_highlighting::highlight(
            //         ui.ctx(),
            //         ui.style(),
            //         &theme,
            //         buf.as_str(),
            //         language,
            //     );
            //     layout_job.wrap.max_width = wrap_width;
            //     ui.fonts_mut(|f| f.layout_job(layout_job))
            // };
            // let code = &mut content.clone();
            // egui::ScrollArea::vertical().show(ui, |ui| {
            //     ui.add(
            //         egui::TextEdit::multiline(code)
            //             .font(egui::TextStyle::Monospace)
            //             .code_editor()
            //             .desired_rows(10)
            //             .lock_focus(true)
            //             .desired_width(f32::INFINITY)
            //             .layouter(&mut layouter),
            //     );
            // });
        }
    }
}
