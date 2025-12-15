use std::time::Duration;
use super::generation_tab::{DURATION_MIN, DURATION_MAX};

/**
 * Returns the minimum and maximum durations, expressed in seconds (f64),
 * used as bounds when converting between a duration and the slider position.
 */
fn duration_range_secs() -> (f64, f64) {
    (DURATION_MIN.as_secs_f64(), DURATION_MAX.as_secs_f64())
}

/**
 * Converts the slider position (between 0.0 and 1.0) into an actual Duration,
 * by logarithmically interpolating between DURATION_MIN and DURATION_MAX.
 */
fn slider_to_duration(value: f32) -> Duration {
    let (min, max) = duration_range_secs();
    let v = value.clamp(0.0, 1.0) as f64;

    let log_secs = min.ln() + (max.ln() - min.ln()) * v;
    let secs = log_secs.exp();
    let rounded_secs = (secs / 60.0).round() * 60.0;

    Duration::from_secs_f64(rounded_secs.clamp(min, max).round())
}

/**
 * Converts a real Duration into a slider position (between 0.0 and 1.0),
 * based on its proportion within the [DURATION_MIN, DURATION_MAX] interval.
 */
pub fn duration_to_slider(d: Duration) -> f32 {
    let (min, max) = duration_range_secs();
    let secs = d.as_secs_f64().clamp(min, max);

    let numerator = secs.ln() - min.ln();
    let denominator = max.ln() - min.ln();
    let v = if denominator == 0.0 {
        0.0
    } else {
        numerator / denominator
    };
    v.clamp(0.0, 1.0) as f32
}

/**
 * Produces a human-readable duration string from the given slider position.
 */
pub fn duration_string_from_slider(value: f32) -> String {
    let duration = slider_to_duration(value);
    humantime::format_duration(duration).to_string()
}

/**
 * Converts a human-readable duration string into a slider position.
 */
pub fn slider_from_duration_string(duration_str: String) -> Option<f32> {
    let result = humantime::parse_duration(&duration_str);
    match result {
        Ok(duration) => Some(duration_to_slider(duration)),
        Err(_) => None,
    }
}