use eframe::egui;

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
        if ui.button("Clear").clicked() {
            *value = None;
        }
    });
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

    if ui.button("Clear").clicked() {
        *value = None;
    }
}
