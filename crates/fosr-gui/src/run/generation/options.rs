//! Generation options UI components.
//!
//! This module provides the UI for configuring PCAP generation parameters:
//! duration, start time, timezone, seed, and advanced options.

use crate::run::state::RunState;

use super::ui_components::{show_field_error, timezone_picker};
use super::validation::{
    first_invalid_param, validate_duration, validate_optional_u64, validate_timezone,
};
use crate::shared::colors::{COLOR_ERROR, COLOR_TEXT_MUTED};
use crate::shared::ui_constants::{
    DURATION_TEXT_WIDTH, GENERATION_COL1_MIN_WIDTH, GENERATION_COL2_MIN_WIDTH,
    GENERATION_OPTIONS_COLUMNS, SEED_INPUT_WIDTH, SPACING_LG,
};
use crate::shared::ui_utils::info_icon;
use crate::timepicker::TimePickerButton;
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
pub fn show_generation_options(ui: &mut egui::Ui, state: &mut RunState) {
    ui.columns(GENERATION_OPTIONS_COLUMNS, |cols| {
        // --- Column 1: Duration & Time ---
        let col1 = &mut cols[0];
        col1.set_min_width(GENERATION_COL1_MIN_WIDTH);

        // Duration
        col1.horizontal(|ui| {
            ui.label("Duration");
            info_icon(ui, "Minimum pcap traffic duration described in human-friendly time, such as \"30m\", \"1h\", \"2d\" or \"2days 30min 5s\".");

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
                    Ok(_) => {
                        state.generation.duration_validation.set_ok();
                    }
                    Err(msg) => {
                        state.generation.duration_validation.set_err(msg);
                    }
                }
            }

            show_field_error(ui, &state.generation.duration_validation);
        });

        col1.add_space(SPACING_LG);

        // Use current time
        col1.horizontal(|ui| {
            ui.checkbox(&mut state.generation.use_current_time, "Use current time for start time");
            info_icon(ui, "Beginning time of the pcap. By default, use the current time. For deterministic generation, you must specify this along with duration, timezone and seed.");
        });

        if !state.generation.use_current_time {
            col1.horizontal(|ui| {
                ui.label("Start time");
                let current_year = Local::now().date_naive().year();
                ui.add(
                    DatePickerButton::new(&mut state.generation.start_date)
                        .start_end_years((current_year - 5)..=(current_year + 30)),
                );
                ui.add(
                    TimePickerButton::new(&mut state.generation.start_hour)
                        .show_seconds(true)
                        .use_dragvalue(true),
                );
            });

            col1.add_space(SPACING_LG);

            col1.horizontal(|ui| {
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
                info_icon(ui, "Timezone used for realistic work hours. Use an IANA time zone (like Europe/Paris) or an abbreviation (like CET). The offset is assumed constant during the generation time range.");

                if !state.generation.use_local_timezone {
                    timezone_picker(ui, &mut state.generation);

                    let result = validate_timezone(&state.generation.timezone_input);
                    if result.is_ok() {
                        state.generation.timezone_validation.set_ok();
                    } else {
                        state.generation.timezone_validation.set_err(result.err().unwrap());
                    }
                }
            });
        } else {
            state.generation.timezone_validation.set_ok();
        }

        // Show the equivalent UTC start time (or error if timezone is invalid)
        let utc_text: Option<String> = if state.generation.use_current_time {
            Some(chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string())
        } else {
            let local_dt = state
                .generation
                .start_date
                .and_time(state.generation.start_hour);

            let utc = if state.generation.use_local_timezone {
                Local::now()
                    .timezone()
                    .from_local_datetime(&local_dt)
                    .earliest()
                    .map(|dt| dt.with_timezone(&chrono::Utc))
            } else {
                state
                    .generation
                    .timezone_input
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
        };

        if let Some(text) = utc_text {
            col1.label(
                egui::RichText::new(format!("Start time (UTC): {}", text))
                    .color(COLOR_TEXT_MUTED),
            );
        }

        // --- Column 2: Seed & Advanced ---
        let col2 = &mut cols[1];
        col2.set_min_width(GENERATION_COL2_MIN_WIDTH);

        // Seed
        col2.horizontal(|ui| {
            ui.checkbox(&mut state.generation.use_seed, "Seed");
            info_icon(ui, "Seed for random number generation. For deterministic generation, you must also specify duration, start time, and timezone.");

            if state.generation.use_seed {
                let response = ui.add(
                    egui::TextEdit::singleline(&mut state.generation.seed_input)
                        .hint_text("enter a seed value")
                        .desired_width(SEED_INPUT_WIDTH),
                );

                if response.changed() {
                    match validate_optional_u64(&state.generation.seed_input) {
                        Ok(_) => {
                            state.generation.seed_validation.set_ok();
                        }
                        Err(msg) => {
                            state.generation.seed_validation.set_err(msg);
                        }
                    }
                }

                show_field_error(ui, &state.generation.seed_validation);
            } else {
                state.generation.seed_validation.set_ok();
            }
        });

        col2.add_space(SPACING_LG);

        // Advanced options
        col2.horizontal(|ui| {
            ui.checkbox(&mut state.generation.taint, "Taint the packets");
            info_icon(ui, "Taint the packets with special markers for identification.");
        });
        col2.horizontal(|ui| {
            ui.checkbox(&mut state.generation.order_pcap, "Order temporally");
            info_icon(ui, "Enable temporal sorting of the generated pcap. Disable to reduce significantly the RAM usage.");
        });

        col2.add_space(SPACING_LG);

        // Validation errors
        if let Some((name, spec, err)) = first_invalid_param(&state.generation) {
            col2.colored_label(
                COLOR_ERROR,
                format!("Invalid parameter: {name}. Expected: {spec}. ({err})"),
            );
        }
    });
}
