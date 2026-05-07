//! Generation options UI components.
//!
//! This module provides the UI for configuring PCAP generation parameters:
//! duration, start time, timezone, seed, and advanced options.

use crate::run::state::RunTabState;

use super::validation::{
    first_invalid_param, render_field_error, validate_duration,
    validate_timezone,
};
use crate::shared::constants::colors::{COLOR_ERROR, COLOR_TEXT_MUTED};
use crate::shared::constants::ui::{
    DURATION_TEXT_WIDTH, GENERATION_COL1_MIN_WIDTH, GENERATION_COL2_MIN_WIDTH,
    GENERATION_OPTIONS_COLUMNS, SEED_INPUT_WIDTH, SPACING_LG,
};
use crate::shared::widgets::helpers::info_icon_with_tooltip;
use crate::shared::widgets::time_picker::button::TimePickerButton;
use crate::shared::widgets::timezone_picker::timezone_picker;
use chrono::{Datelike, Local, TimeZone};
use chrono_tz::Tz;
use eframe::egui::{self, Widget};
use egui_extras::DatePickerButton;

/// Show the generation options panel with two columns.
///
/// **Column 1:** Duration and time settings
/// - Duration input with preset buttons (5min, 1h, 24h)
/// - Start time toggle (current time vs custom)
/// - Timezone selection
///
/// **Column 2:** Seed and advanced options
/// - Optional seed for deterministic generation
/// - Taint packets option
/// - Temporal ordering option
pub fn render_generation_options(ui: &mut egui::Ui, state: &mut RunTabState) {
    ui.columns(GENERATION_OPTIONS_COLUMNS, |cols| {
        render_duration_column(&mut cols[0], state);
        render_seed_column(&mut cols[1], state);
    });
}

/// Column 1: Duration input, start time picker, and timezone selection.
fn render_duration_column(col: &mut egui::Ui, state: &mut RunTabState) {
    col.set_min_width(GENERATION_COL1_MIN_WIDTH);

    render_duration_input(col, state);
    col.add_space(SPACING_LG);

    render_start_time_options(col, state);
    render_utc_preview(col, state);
}

/// Duration input with preset buttons and validation.
fn render_duration_input(ui: &mut egui::Ui, state: &mut RunTabState) {
    ui.horizontal(|ui| {
        ui.label("Duration");
        info_icon_with_tooltip(ui, "Minimum pcap traffic duration described in human-friendly time, such as \"30m\", \"1h\", \"2d\" or \"2days 30min 5s\".");

        // Preset buttons
        for preset in ["5min", "1h", "24h"] {
            if ui.small_button(preset).clicked() {
                state.generation.duration_str = preset.to_string();
                state.generation.duration_validation.set_ok();
            }
        }

        let text_response = egui::TextEdit::singleline(&mut state.generation.duration_str)
            .desired_width(DURATION_TEXT_WIDTH)
            .hint_text("ex: 30m, 1h, 2d")
            .ui(ui);

        if text_response.changed() {
            match validate_duration(&state.generation.duration_str) {
                Ok(_) => state.generation.duration_validation.set_ok(),
                Err(msg) => state.generation.duration_validation.set_err(msg),
            }
        }

        render_field_error(ui, &state.generation.duration_validation);
    });
}

/// Start time toggle and custom time picker with timezone selection.
fn render_start_time_options(ui: &mut egui::Ui, state: &mut RunTabState) {
    ui.horizontal(|ui| {
        ui.checkbox(&mut state.generation.use_current_time, "Use current time for start time");
        info_icon_with_tooltip(ui, "Beginning time of the pcap. By default, use the current time. For deterministic generation, you must specify this along with duration, timezone and seed.");
    });

    if state.generation.use_current_time {
        state.generation.timezone_validation.set_ok();
        return;
    }

    // Custom start time picker
    ui.horizontal(|ui| {
        ui.label("Start time");
        let current_year = Local::now().date_naive().year();
        ui.add(
            DatePickerButton::new(&mut state.generation.start_date)
                .start_end_years((current_year - 5)..=(current_year + 30)),
        );
        ui.add(
            TimePickerButton::new(&mut state.generation.start_time)
                .show_seconds(true)
                .use_drag_value(true),
        );
    });

    ui.add_space(SPACING_LG);

    render_timezone_picker(ui, state);
}

/// Timezone picker with local/custom toggle.
fn render_timezone_picker(ui: &mut egui::Ui, state: &mut RunTabState) {
    ui.horizontal(|ui| {
        if ui
            .checkbox(&mut state.generation.use_local_timezone, "Use local timezone")
            .clicked()
        {
            if state.generation.use_local_timezone {
                state.generation.timezone_input = String::new();
                state.generation.timezone_validation.set_ok();
            } else {
                state.generation.timezone_input = Tz::CET.to_string();
            }
        }
        info_icon_with_tooltip(ui, "Timezone used for realistic work hours. Use an IANA time zone (like Europe/Paris) or an abbreviation (like CET). The offset is assumed constant during the generation time range.");

        if !state.generation.use_local_timezone {
            timezone_picker(ui, &mut state.generation.timezone_input);

            match validate_timezone(&state.generation.timezone_input) {
                Ok(()) => state.generation.timezone_validation.set_ok(),
                Err(msg) => state.generation.timezone_validation.set_err(msg),
            }
        }
    });
}

/// Displays the UTC equivalent of the selected start time.
fn render_utc_preview(ui: &mut egui::Ui, state: &mut RunTabState) {
    let utc_text = compute_utc_text(state);

    if let Some(text) = utc_text {
        ui.label(
            egui::RichText::new(format!("Start time (UTC): {}", text))
                .color(COLOR_TEXT_MUTED),
        );
    }
}

/// Computes the UTC representation of the selected start time.
/// Returns None if using local timezone and the datetime is ambiguous.
fn compute_utc_text(state: &RunTabState) -> Option<String> {
    if state.generation.use_current_time {
        return Some(chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string());
    }

    let local_dt = state.generation.start_date.and_time(state.generation.start_time);

    let utc = if state.generation.use_local_timezone {
        Local::now()
            .timezone()
            .from_local_datetime(&local_dt)
            .earliest()
            .map(|dt| dt.with_timezone(&chrono::Utc))
    } else {
        state.generation.timezone_input
            .parse::<Tz>()
            .ok()
            .and_then(|tz| local_dt.and_local_timezone(tz).earliest())
            .map(|dt| dt.with_timezone(&chrono::Utc))
    };

    utc.map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
        .or_else(|| {
            if !state.generation.use_local_timezone {
                Some("select a valid timezone".to_string())
            } else {
                None
            }
        })
}

/// Column 2: Seed input and advanced options (taint, temporal ordering).
fn render_seed_column(col: &mut egui::Ui, state: &mut RunTabState) {
    col.set_min_width(GENERATION_COL2_MIN_WIDTH);

    render_seed_input(col, state);
    col.add_space(SPACING_LG);

    render_advanced_options(col, state);
    col.add_space(SPACING_LG);

    render_validation_errors(col, state);
}

/// Seed input (accepts any text, hashed to u64 for generation).
fn render_seed_input(ui: &mut egui::Ui, state: &mut RunTabState) {
    ui.horizontal(|ui| {
        ui.checkbox(&mut state.generation.use_seed, "Seed");
        info_icon_with_tooltip(ui, "Seed for random number generation. Any text is accepted: integers are used as-is, other values are converted to an integer by hashing. For deterministic generation, you must also specify duration, start time, and timezone.");

        if state.generation.use_seed {
            ui.add(
                egui::TextEdit::singleline(&mut state.generation.seed_input)
                    .hint_text("enter a seed value")
                    .desired_width(SEED_INPUT_WIDTH),
            );
        }
    });
}

/// Advanced options: taint packets and temporal ordering.
fn render_advanced_options(ui: &mut egui::Ui, state: &mut RunTabState) {
    ui.horizontal(|ui| {
        ui.checkbox(&mut state.generation.taint, "Taint the packets");
        info_icon_with_tooltip(ui, "Taint the packets with special markers for identification.");
    });
    ui.horizontal(|ui| {
        ui.checkbox(&mut state.generation.order_pcap, "Order temporally");
        info_icon_with_tooltip(ui, "Enable temporal sorting of the generated pcap. Disable to reduce significantly the RAM usage.");
    });
}

/// Shows the first validation error if any parameter is invalid.
fn render_validation_errors(ui: &mut egui::Ui, state: &RunTabState) {
    if let Some((name, spec, err)) = first_invalid_param(&state.generation) {
        ui.colored_label(
            COLOR_ERROR,
            format!("Invalid parameter: {name}. Expected: {spec}. ({err})"),
        );
    }
}
