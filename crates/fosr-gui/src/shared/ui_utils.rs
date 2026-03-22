//! Reusable UI widgets: info icons, optional string editors, toggles, labels.

use eframe::egui::{self, TextFormat, text::LayoutJob};

/// Display a small info icon with a tooltip.
pub fn info_icon(ui: &mut egui::Ui, tooltip: &str) {
    ui.add_space(-4.0);
    ui.label(
        egui::RichText::new("ℹ")
            .color(egui::Color32::GRAY)
            .size(14.0),
    )
    .on_hover_cursor(egui::CursorIcon::Help)
    .on_hover_ui(|ui| {
        ui.set_max_width(300.0);
        ui.label(tooltip);
    });
}

/// Displays an editor for an `Option<String>` field in an egui UI.
///
/// This helper is designed for configuration fields that are **optional**:
/// - If the field is `None`, the text input starts empty.
/// - If the user types a non-empty value, the field becomes `Some(String)`.
/// - If the user clears the input (or clicks the "Clear" button),
///   the field is set back to `None`.
///
/// # Parameters
/// - `ui`: The egui UI context.
/// - `label`: The label displayed next to the input field.
/// - `value`: The optional string being edited.
/// - `hint`: Placeholder text shown when the field is empty.
///
/// # Typical usage
/// ```ignore
/// edit_optional_string(
///     ui,
///     "Author (optional):",
///     &mut model.metadata.author,
///     "Jane Doe",
/// );
/// ```
pub fn edit_optional_string(
    ui: &mut egui::Ui,
    label: &str,
    value: &mut Option<String>,
    hint: &str,
) {
    ui.horizontal(|ui| {
        ui.label(label);

        // Temporary editable buffer:
        // - empty if the value is None
        // - otherwise contains the current value
        let mut buffer = value.clone().unwrap_or_default();

        let response = ui.add(egui::TextEdit::singleline(&mut buffer).hint_text(hint));

        // Commit changes back to the Option<String>
        if response.changed() {
            let trimmed = buffer.trim();
            if trimmed.is_empty() {
                *value = None;
            } else {
                *value = Some(trimmed.to_string());
            }
        }

        // Explicit clear button
        if ui
            .button(egui_material_icons::icons::ICON_CLEAR)
            .on_hover_text("Clear")
            .clicked()
        {
            *value = None;
        }
    });
}

/// Segmented toggle button between two options.
/// Displays two buttons side by side in a grouped frame.
/// Rendering order follows the parent layout direction.
pub fn labeled_toggle(
    ui: &mut egui::Ui,
    is_first_selected: &mut bool,
    first_label: &str,
    second_label: &str,
    tooltip_first: &str,
    tooltip_second: &str,
) {
    // Use a group frame with tight padding to auto-size around the content
    let resp = egui::Frame::group(ui.style())
        .inner_margin(3.0)
        .show(ui, |ui| {
            // Remove the hover stroke on selectable labels inside this toggle
            ui.style_mut().visuals.widgets.hovered.bg_stroke = egui::Stroke::NONE;
            ui.spacing_mut().item_spacing = egui::vec2(3.0, 0.0);
            ui.horizontal(|ui| {
                let first = ui.selectable_label(*is_first_selected, first_label);
                if first.clicked() {
                    *is_first_selected = true;
                }
                first.on_hover_text(tooltip_first);

                let second = ui.selectable_label(!*is_first_selected, second_label);
                if second.clicked() {
                    *is_first_selected = false;
                }
                second.on_hover_text(tooltip_second);
            });
        });
    let _ = resp;
}

/// Displays a multiline editor for an `Option<String>`.
///
/// - `None` is represented as an empty text box.
/// - If the user enters non-empty text, it becomes `Some(text)`.
/// - If the user clears the text (or clicks "Clear"), it becomes `None`.
///
/// This prevents exporting empty strings as `''` in YAML.
pub fn edit_optional_multiline_string(
    ui: &mut egui::Ui,
    label: &str,
    value: &mut Option<String>,
    hint: &str,
    rows: usize,
) {
    ui.label(label);

    let mut buffer = value.clone().unwrap_or_default();
    let response = ui.add(
        egui::TextEdit::multiline(&mut buffer)
            .desired_rows(rows)
            .hint_text(hint),
    );

    if response.changed() {
        let trimmed = buffer.trim();
        if trimmed.is_empty() {
            *value = None;
        } else {
            *value = Some(buffer); // garde les retours à la ligne
        }
    }

    if ui
        .button(egui_material_icons::icons::ICON_CLEAR)
        .on_hover_text("Clear")
        .clicked()
    {
        *value = None;
    }
}

// Helper for required label with red *
pub fn required_label(ui: &mut egui::Ui, text: &str) {
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
