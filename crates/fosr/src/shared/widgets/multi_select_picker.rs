//! Multi-select picker widget with search and checkboxes.
//!
//! Built on top of [`SearchableCombo`].
//! Shows a combo button that opens a popup with a searchable list of checkboxes.
//! The popup stays open while toggling items, allowing multi-selection.

use super::searchable_combo::SearchableCombo;
use eframe::egui;

/// Render a multi-select picker with search and checkboxes.
///
/// # Arguments
/// * `ui` - The egui UI context
/// * `id` - Unique identifier for this picker instance
/// * `items` - Full list of available items to choose from
/// * `selected` - Mutably shared vector of currently selected items (modified in-place)
/// * `width` - Width of the combo button in pixels
pub fn multi_select_picker(
    ui: &mut egui::Ui,
    id: impl Into<egui::Id>,
    items: &[&str],
    selected: &mut Vec<String>,
    width: f32,
) {
    let summary = build_summary(selected);

    SearchableCombo::new(id, &summary)
        .width(width)
        .show(ui, |ui, filter| {
            let mut any_shown = false;

            for item in items {
                if !filter.is_empty() && !item.to_lowercase().contains(filter) {
                    continue;
                }

                any_shown = true;
                let is_selected = selected.iter().any(|s| s == *item);
                let mut checked = is_selected;

                ui.checkbox(&mut checked, *item);

                if checked && !is_selected {
                    selected.push(item.to_string());
                } else if !checked && is_selected {
                    selected.retain(|s| s != *item);
                }
            }

            if !any_shown {
                ui.label(egui::RichText::new("No matching items").italics().weak());
            }
        });
}

/// Build a summary string for the selected items.
///
/// Shows up to 3 item names, then "N selected" for larger sets.
/// Shows "None" when empty.
fn build_summary(selected: &[String]) -> String {
    if selected.is_empty() {
        "None".to_string()
    } else if selected.len() <= 3 {
        selected.join(", ")
    } else {
        format!("{} selected", selected.len())
    }
}
