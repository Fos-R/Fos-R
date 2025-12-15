use chrono_tz::TZ_VARIANTS;
use eframe::{egui, egui::PopupCloseBehavior};
use super::generation_tab::{GenerationTabState, UiStatus};
use super::generation_validation::FieldValidation;

/**
 * Display the error in red
 */
pub fn show_field_error(ui: &mut egui::Ui, validation: &FieldValidation) {
    if let Some(msg) = &validation.error {
        ui.add_space(6.0);
        ui.colored_label(egui::Color32::RED, msg);
    }
}

pub fn show_status(ui: &mut egui::Ui, status: &UiStatus) {
    match status {
        UiStatus::Idle => {}
        UiStatus::Generating => {
            ui.label("Generating file…");
        }
        UiStatus::Generated => {
            ui.label("File generated. You can save it.");
        }
        #[cfg(not(target_arch = "wasm32"))]
        UiStatus::Saved(msg) => {
            ui.label(format!("File saved. {}", msg));
        }
        #[cfg(not(target_arch = "wasm32"))]
        UiStatus::Error(msg) => {
            ui.colored_label(egui::Color32::RED, format!("Error: {msg}"));
        }
    }
}

pub fn timezone_picker(ui: &mut egui::Ui, state: &mut GenerationTabState) {
    egui::ComboBox::from_id_salt("timezone")
        .selected_text(&state.timezone_input)
        .width(200.0)
        .close_behavior(PopupCloseBehavior::CloseOnClickOutside)
        .show_ui(ui, |ui| {
            ui.set_max_width(240.0);

            // Define a unique ID for focus and state tracking
            let edit_id = ui.make_persistent_id("timezone_search_input");

            // Add the text edit widget
            ui.add(
                egui::TextEdit::singleline(&mut state.timezone_input)
                    .hint_text("Search...")
                    .id(edit_id),
            );

            // Handle Auto-focus & Auto-select on initial open
            if ui.memory(|m| m.focused().is_none()) {
                ui.memory_mut(|m| m.request_focus(edit_id));
            }

            ui.separator();

            // List with filtering
            let filter = state.timezone_input.to_lowercase();
            for tz in TZ_VARIANTS {
                let tz_str = tz.to_string();
                if filter.is_empty() || tz_str.to_lowercase().contains(&filter) {
                    if ui
                        .selectable_label(state.timezone_input == tz_str, &tz_str)
                        .clicked()
                    {
                        state.timezone_input = tz_str;
                        // Manually close the popup
                        ui.close();
                    }
                }
            }
        });
}