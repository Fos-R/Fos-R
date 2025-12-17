use crate::configuration::configuration_file::{
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
