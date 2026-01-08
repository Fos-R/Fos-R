use crate::shared::configuration_file::{
    ConfigurationFileState, configuration_file_picker, load_config_file_contents,
};
use eframe::egui;

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

        // --- desc (optional, multiline) ---
        ui.label("Description:");
        {
            let desc = model.metadata.desc.get_or_insert_with(String::new);
            ui.add(
                egui::TextEdit::multiline(desc)
                    .desired_rows(3)
                    .hint_text("Optional description"),
            );
        }

        // --- author (optional) ---
        ui.horizontal(|ui| {
            ui.label("Author:");
            let author = model.metadata.author.get_or_insert_with(String::new);
            ui.text_edit_singleline(author);
        });

        // --- date (optional, keep as string for now) ---
        // TODO : utiliser un date picker comme dans l'onglet génération
        ui.horizontal(|ui| {
            ui.label("Date:");
            let date = model.metadata.date.get_or_insert_with(String::new);
            ui.text_edit_singleline(date)
                .on_hover_text("Optional. Example: 2025/11/05");
        });

        // --- version (optional) ---
        ui.horizontal(|ui| {
            ui.label("Version:");
            let version = model.metadata.version.get_or_insert_with(String::new);
            ui.text_edit_singleline(version);
        });

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
