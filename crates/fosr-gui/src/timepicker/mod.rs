// This module is based on egui_timepicker v0.1.0 (https://crates.io/crates/egui_timepicker).
//
// Changes from the original:
// - Use theme-aware colors instead of hardcoded Color32::WHITE (supports light mode)
// - Auto-advance clock face from Hour → Minute → Second on click/drag release
// - Highlight the active drag value input with a selection-colored border
// - Switch clock face to match whichever drag value is being interacted with
// - Remove unused builder methods (id_salt, show_icon, format, show_clockface, use_12_hour_clock)

mod button;
mod popup;

pub use button::TimePickerButton;
