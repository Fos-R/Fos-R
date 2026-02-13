use super::generation_tab::{DURATION_MAX, DURATION_MIN, GenerationTabState};
use chrono_tz::Tz;
use std::time::Duration;

/// Structure to handle inputs errors from the user
#[derive(Default, Clone)]
pub struct FieldValidation {
    pub error: Option<String>,
}

impl FieldValidation {
    pub fn set_ok(&mut self) {
        self.error = None;
    }
    pub fn set_err(&mut self, msg: impl Into<String>) {
        self.error = Some(msg.into());
    }
}

// Spec expected for each parameter
const SPEC_DURATION: &str = "a duration between 1 min and 3 days (e.g. 30m, 1h, 2d)";
const SPEC_SEED: &str = "an unsigned integer (u64) or empty for random";
const SPEC_TIMEZONE: &str = "a valid timezone";

// return the first invalid parameter
pub fn first_invalid_param(
    state: &GenerationTabState,
) -> Option<(&'static str, &'static str, String)> {
    if let Some(err) = &state.duration_validation.error {
        return Some(("Duration", SPEC_DURATION, err.clone()));
    }
    if let Some(err) = &state.seed_validation.error {
        return Some(("Seed", SPEC_SEED, err.clone()));
    }
    if let Some(err) = &state.timezone_validation.error {
        return Some(("Timezone", SPEC_TIMEZONE, err.clone()));
    }
    None
}

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


pub fn validate_optional_u64(input: &str) -> Result<Option<u64>, String> {
    let s = input.trim();
    if s.is_empty() {
        return Ok(None);
    }
    s.parse::<u64>()
        .map(Some)
        .map_err(|_| "Invalid value".to_string())
}

pub fn validate_timezone(input: &str) -> Result<(), String> {
    let parsed = input.parse::<Tz>();
    match parsed {
        Ok(_) => Ok(()),
        Err(_) => Err("Invalid value".to_string()),
    }
}
