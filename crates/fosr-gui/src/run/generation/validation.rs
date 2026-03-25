//! Input validation helpers for duration, seed, and timezone fields.

use super::state::{DURATION_MAX, DURATION_MIN, GenerationState};
use crate::shared::constants::colors::COLOR_ERROR;
use crate::shared::constants::ui::SPACING_MD;
use chrono_tz::Tz;
use eframe::egui;
use std::time::Duration;

/// Holds validation state for a single input field.
#[derive(Default, Clone)]
pub struct FieldValidation {
    pub error: Option<String>,
}

impl FieldValidation {
    /// Clears any existing error.
    pub fn set_ok(&mut self) {
        self.error = None;
    }

    /// Sets an error message.
    pub fn set_err(&mut self, msg: impl Into<String>) {
        self.error = Some(msg.into());
    }
}

/// Display the error message in red below the field.
pub fn show_field_error(ui: &mut egui::Ui, validation: &FieldValidation) {
    if let Some(msg) = &validation.error {
        ui.add_space(SPACING_MD);
        ui.colored_label(COLOR_ERROR, msg);
    }
}

// Expected format for each parameter (shown in error messages)
const SPEC_DURATION: &str = "a duration between 1 min and 3 days (e.g. 30m, 1h, 2d)";
const SPEC_SEED: &str = "an unsigned integer (u64) or empty for random";
const SPEC_TIMEZONE: &str = "a valid timezone";

/// Returns the first invalid parameter (name, expected spec, error message).
pub fn first_invalid_param(state: &GenerationState) -> Option<(&'static str, &'static str, &str)> {
    [
        ("Duration", SPEC_DURATION, &state.duration_validation),
        ("Seed", SPEC_SEED, &state.seed_validation),
        ("Timezone", SPEC_TIMEZONE, &state.timezone_validation),
    ]
    .into_iter()
    .find_map(|(name, spec, validation)| {
        validation.error.as_ref().map(|err| (name, spec, err.as_str()))
    })
}

/// Validates a human-readable duration string and checks bounds.
pub fn validate_duration(duration_str: &str) -> Result<Duration, String> {
    let d = humantime::parse_duration(duration_str).map_err(|_| "Invalid value".to_string())?;

    if d < DURATION_MIN || d > DURATION_MAX {
        return Err(format!(
            "Out of range ({} – {})",
            humantime::format_duration(DURATION_MIN),
            humantime::format_duration(DURATION_MAX),
        ));
    }
    Ok(d)
}

/// Validates an optional u64 input (empty is valid, means "use random").
pub fn validate_optional_u64(input: &str) -> Result<Option<u64>, String> {
    let s = input.trim();
    if s.is_empty() {
        return Ok(None);
    }
    s.parse::<u64>()
        .map(Some)
        .map_err(|_| "Invalid value".to_string())
}

/// Validates an IANA timezone string.
pub fn validate_timezone(input: &str) -> Result<(), String> {
    input
        .parse::<Tz>()
        .map(|_| ())
        .map_err(|_| "Invalid value".to_string())
}
