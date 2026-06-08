//! Timezone picker widget with search functionality.
//!
//! Uses [`SearchableCombo`] for the combo button and searchable popup,
//! with timezone-specific single-select logic.

use super::searchable_combo::SearchableCombo;
use crate::shared::constants::ui::{
    TIMEZONE_LIST_MAX_HEIGHT, TIMEZONE_PICKER_WIDTH, TIMEZONE_POPUP_MAX_HEIGHT,
};
use chrono_tz::TZ_VARIANTS;
use eframe::egui;

/// Timezone picker with search functionality.
///
/// Displays a searchable combo that allows selecting a timezone from the
/// full IANA timezone database. Clicking a timezone closes the popup.
pub fn timezone_picker(ui: &mut egui::Ui, timezone_input: &mut String) {
    SearchableCombo::new("tz_popup", timezone_input.clone())
        .width(TIMEZONE_PICKER_WIDTH)
        .popup_max_height(TIMEZONE_POPUP_MAX_HEIGHT)
        .list_max_height(TIMEZONE_LIST_MAX_HEIGHT)
        .show(ui, |ui, filter| {
            ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Extend);

            for tz in TZ_VARIANTS {
                let tz_str = tz.to_string();
                if (filter.is_empty() || tz_str.to_lowercase().contains(filter))
                    && ui
                        .selectable_label(*timezone_input == tz_str, &tz_str)
                        .clicked()
                {
                    *timezone_input = tz_str;
                    ui.close();
                }
            }
        });
}
