use crate::ui::generate::generate;
use chrono::NaiveDate;
use chrono_tz::{TZ_VARIANTS, Tz};
use eframe::egui;
use eframe::egui::{PopupCloseBehavior, SliderClamping, Widget};
use egui_extras::DatePickerButton;
use rfd::FileHandle;
use std::io::Error;
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;
// WASM-specific imports
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_futures;

// Time interval for the slider.
const DURATION_MIN: Duration = Duration::from_secs(60); // 1 min
const DURATION_MAX: Duration = Duration::from_secs(3 * 24 * 3600); // 3 days

// Spec expected for each parameter
const SPEC_DURATION: &str = "a duration between 1 min and 3 days (e.g. 30m, 1h, 2d)";
const SPEC_START_HOUR: &str = "an hour in HH:MM format";
const SPEC_SEED: &str = "an unsigned integer (u64) or empty for random";
const SPEC_TIMEZONE: &str = "a valid timezone";

// return the first invalid parameter
fn first_invalid_param(state: &GenerationTabState) -> Option<(&'static str, &'static str, String)> {
    if let Some(err) = &state.duration_validation.error {
        return Some(("Duration", SPEC_DURATION, err.clone()));
    }
    if let Some(err) = &state.start_hour_validation.error {
        return Some(("Start hour", SPEC_START_HOUR, err.clone()));
    }
    if let Some(err) = &state.seed_validation.error {
        return Some(("Seed", SPEC_SEED, err.clone()));
    }
    if let Some(err) = &state.timezone_validation.error {
        return Some(("Timezone", SPEC_TIMEZONE, err.clone()));
    }
    None
}

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
fn duration_to_slider(d: Duration) -> f32 {
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
fn duration_string_from_slider(value: f32) -> String {
    let duration = slider_to_duration(value);
    humantime::format_duration(duration).to_string()
}

/**
 * Converts a human-readable duration string into a slider position.
 */
fn slider_from_duration_string(duration_str: String) -> Option<f32> {
    let result = humantime::parse_duration(&duration_str);
    match result {
        Ok(duration) => Some(duration_to_slider(duration)),
        Err(_) => None,
    }
}

/**
 * Structure to handle inputs errors from the user
 */
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

pub enum UiStatus {
    Idle,
    Generating,
    Generated,
    #[cfg(not(target_arch = "wasm32"))]
    Saved(String),
    #[cfg(not(target_arch = "wasm32"))]
    Error(String),
}

/**
 * Represents the state of the generation tab.
 */
pub struct GenerationTabState {
    pub picked_config_file: Option<FileHandle>,
    #[cfg(target_arch = "wasm32")]
    pub config_file_receiver: Option<Receiver<Option<FileHandle>>>,
    pub progress: f32,
    pub progress_receiver: Option<Receiver<f32>>,
    pub pcap_bytes: Option<Vec<u8>>,
    pub pcap_receiver: Option<Receiver<Vec<u8>>>,
    pub status: UiStatus,
    // Validation states
    pub duration_validation: FieldValidation,
    pub start_hour_validation: FieldValidation,
    pub seed_validation: FieldValidation,
    pub timezone_validation: FieldValidation,
    // Parameters
    pub order_pcap: bool,
    pub taint: bool,

    pub duration_str: String,
    pub duration_slider_value: f32,

    pub seed_input: String,

    pub timezone_input: String,
    pub use_local_timezone: bool,

    pub start_date: NaiveDate,
    pub start_hour: String,

    pub output_file_name: String,
}

impl Default for GenerationTabState {
    fn default() -> Self {
        let default_duration = "1h".to_string();
        let duration_slider_value = slider_from_duration_string(default_duration.clone()).unwrap();

        Self {
            picked_config_file: None,
            #[cfg(target_arch = "wasm32")]
            config_file_receiver: None,
            progress: 0.0,
            progress_receiver: None,
            pcap_bytes: None,
            pcap_receiver: None,
            status: UiStatus::Idle,
            // Validation states
            duration_validation: FieldValidation::default(),
            start_hour_validation: FieldValidation::default(),
            seed_validation: FieldValidation::default(),
            timezone_validation: FieldValidation::default(),
            // Parameters
            order_pcap: false,
            taint: false,

            duration_str: default_duration,
            duration_slider_value,

            seed_input: String::new(),

            timezone_input: Tz::CET.to_string(),
            use_local_timezone: true,

            start_date: NaiveDate::from_ymd_opt(2025, 1, 1).unwrap(),
            start_hour: "00:00:00".to_string(),

            output_file_name: "output.pcap".to_string(),
        }
    }
}

/**
 * Display the error in red
 */
fn show_field_error(ui: &mut egui::Ui, validation: &FieldValidation) {
    if let Some(msg) = &validation.error {
        ui.add_space(6.0);
        ui.colored_label(egui::Color32::RED, msg);
    }
}

fn show_status(ui: &mut egui::Ui, status: &UiStatus) {
    match status {
        UiStatus::Idle => {}
        UiStatus::Generating => {
            ui.label("Generating file…");
        }
        UiStatus::Generated => {
            ui.label("File generated. You can save it.");
        }
        #[cfg(not(target_arch = "wasm32"))]
        UiStatus::Saved(msg) => {
            ui.label(format!("File saved. {}", msg));
        }
        #[cfg(not(target_arch = "wasm32"))]
        UiStatus::Error(msg) => {
            ui.colored_label(egui::Color32::RED, format!("Error: {msg}"));
        }
    }
}

fn validate_duration(duration_str: &str) -> Result<Duration, String> {
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

fn validate_start_hour(input: &str) -> Result<(), String> {
    let s = input.trim();
    if s.is_empty() {
        return Err("Invalid value".to_string());
    }

    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 3 || parts[0].len() != 2 || parts[1].len() != 2 || parts[2].len() != 2 {
        return Err("Invalid value".to_string());
    }

    let hour = parts[0]
        .parse::<u8>()
        .map_err(|_| "Invalid value".to_string())?;
    let minute = parts[1]
        .parse::<u8>()
        .map_err(|_| "Invalid value".to_string())?;
    let second = parts[2]
        .parse::<u8>()
        .map_err(|_| "Invalid value".to_string())?;

    if hour > 23 || minute > 59 || second > 59 {
        return Err("Invalid value".to_string());
    }

    Ok(())
}

fn validate_optional_u64(input: &str) -> Result<Option<u64>, String> {
    let s = input.trim();
    if s.is_empty() {
        return Ok(None);
    }
    s.parse::<u64>()
        .map(Some)
        .map_err(|_| "Invalid value".to_string())
}

fn validate_timezone(input: &str) -> Result<(), String> {
    let parsed = input.parse::<Tz>();
    match parsed {
        Ok(_) => Ok(()),
        Err(_) => Err("Invalid value".to_string()),
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn show_file_picker_desktop() -> Option<FileHandle> {
    rfd::FileDialog::new()
        .add_filter("Configuration files", &["toml", "json", "yaml", "yml"])
        .set_directory(std::env::current_dir().unwrap_or(std::path::PathBuf::from("/")))
        .pick_file()
        .map(|path| FileHandle::from(path))
}

#[cfg(target_arch = "wasm32")]
async fn show_file_picker_wasm() -> Option<FileHandle> {
    rfd::AsyncFileDialog::new()
        .add_filter("Configuration files", &["toml", "json", "yaml", "yml"])
        .pick_file()
        .await
}

#[cfg(not(target_arch = "wasm32"))]
fn read_config_file_desktop(config_file: &FileHandle) -> String {
    std::fs::read_to_string(config_file.path()).unwrap()
}

#[cfg(target_arch = "wasm32")]
async fn read_config_file_wasm(config_file: &FileHandle) -> String {
    let content = config_file.read().await;
    String::from_utf8(content).expect("Invalid UTF-8")
}

#[cfg(not(target_arch = "wasm32"))]
fn save_file_desktop(data: &[u8], file_name: &str) -> Result<FileHandle, Error> {
    let result = rfd::FileDialog::new()
        .set_directory(std::env::current_dir().unwrap_or(std::path::PathBuf::from("/")))
        .set_file_name(file_name)
        .save_file()
        .map(|path| FileHandle::from(path));

    match result {
        Some(file_handle) => match std::fs::write(file_handle.path(), data) {
            Ok(_) => Ok(file_handle),
            Err(e) => Err(e),
        },
        None => Err(Error::new(std::io::ErrorKind::Other, "No file selected")),
    }
}
#[cfg(target_arch = "wasm32")]
async fn save_file_wasm(data: &[u8], file_name: &str) -> Result<FileHandle, Error> {
    let result = rfd::AsyncFileDialog::new()
        .set_file_name(file_name)
        .save_file()
        .await;
    match result {
        Some(file_handle) => match file_handle.write(data).await {
            Ok(_) => Ok(file_handle),
            Err(e) => Err(e),
        },
        None => Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "No file selected",
        )),
    }
}

pub fn show_generation_tab_content(ui: &mut egui::Ui, state: &mut GenerationTabState) {
    ui.add_space(5.0);

    // --- Configuration File Picker ---
    ui.horizontal(|ui| {
        ui.label("Configuration file:");

        // File Dialog to pick a config file
        if ui.button("Select file").clicked() {
            #[cfg(not(target_arch = "wasm32"))]
            {
                // Only update if a file was actually selected
                let file = show_file_picker_desktop();
                if file.is_some() {
                    state.picked_config_file = file;
                }
            }

            #[cfg(target_arch = "wasm32")]
            {
                let (sender, receiver) = channel();
                state.config_file_receiver = Some(receiver);

                let ctx = ui.ctx().clone();
                wasm_bindgen_futures::spawn_local(async move {
                    let file = show_file_picker_wasm().await;
                    let _ = sender.send(file);
                    ctx.request_repaint();
                });
            }
        }

        #[cfg(target_arch = "wasm32")]
        // Check if we received a file from the async task
        {
            if let Some(receiver) = &state.config_file_receiver {
                if let Ok(file) = receiver.try_recv() {
                    // Only update if a file was actually selected
                    if file.is_some() {
                        state.picked_config_file = file;
                    }
                    state.config_file_receiver = None; // Dialog finished
                }
            }
        }

        // Display the filename of the picked file, or a placeholder
        let filename = state
            .picked_config_file
            .as_ref()
            .map(|file| file.file_name())
            .unwrap_or("No file selected".to_string());

        if state.picked_config_file.is_some() && ui.button("Remove").clicked() {
            state.picked_config_file = None;
        };

        // On desktop: filename with its full path on hover, on WASM: just the filename
        #[cfg(not(target_arch = "wasm32"))]
        {
            let path_text = state
                .picked_config_file
                .as_ref()
                .map(|file| file.path().to_string_lossy().to_string())
                .unwrap_or("Select a configuration file".to_string());
            ui.label(&filename).on_hover_text(path_text);
        }

        #[cfg(target_arch = "wasm32")]
        ui.label(&filename);
    });

    ui.separator();

    // --- Output file name ---
    // This is only required for WASM. On desktop, a file dialog is opened instead.
    #[cfg(target_arch = "wasm32")]
    {
        ui.horizontal(|ui| {
            ui.label("Output file name:");
            egui::TextEdit::singleline(&mut state.output_file_name)
                .desired_width(180.0)
                .ui(ui);
        });

        ui.separator();
    }

    ui.horizontal(|ui| {
        ui.label("Duration");

        let response = egui::TextEdit::singleline(&mut state.duration_str)
            .desired_width(100.0)
            .hint_text("ex: 30m, 1h, 2d")
            .ui(ui);

        if response.changed() {
            match validate_duration(&state.duration_str) {
                Ok(d) => {
                    state.duration_validation.set_ok();
                    state.duration_slider_value = duration_to_slider(d);
                }
                Err(msg) => {
                    state.duration_validation.set_err(msg);
                }
            }
        }

        show_field_error(ui, &state.duration_validation);
    });

    ui.horizontal(|ui| {
        ui.set_width(300.0);
        let response = ui.add(
            egui::Slider::new(&mut state.duration_slider_value, 0.0..=1.0)
                .show_value(false)
                .clamping(SliderClamping::Never),
        );

        if response.changed() {
            let s = duration_string_from_slider(state.duration_slider_value);
            state.duration_str = s;
            state.duration_validation.set_ok();
        }
    });

    ui.add_space(10.0);

    ui.horizontal(|ui| {
        ui.label("Start time");

        ui.add(DatePickerButton::new(&mut state.start_date));

        let response = egui::TextEdit::singleline(&mut state.start_hour)
            .hint_text("HH:MM")
            .desired_width(50.0)
            .ui(ui);

        if response.changed() {
            match validate_start_hour(&state.start_hour) {
                Ok(()) => state.start_hour_validation.set_ok(),
                Err(msg) => state.start_hour_validation.set_err(msg),
            }
        }

        show_field_error(ui, &state.start_hour_validation);
    });

    ui.add_space(10.0);

    ui.horizontal(|ui| {
        ui.checkbox(&mut state.use_local_timezone, "Use local timezone");
        if state.use_local_timezone {
            // Reset the timezone
            state.timezone_input = String::new();
        } else {
            // Display a dropdown button to select a timezone
            let initial_selected: String;
            if state.timezone_input.is_empty() {
                state.timezone_input = Tz::CET.to_string();
                initial_selected = state.timezone_input.clone();
            } else {
                initial_selected = state.timezone_input.clone();
            }
            egui::ComboBox::from_id_salt("timezone")
                .selected_text(&state.timezone_input)
                .width(200.0)
                .close_behavior(PopupCloseBehavior::CloseOnClickOutside)
                .show_ui(ui, |ui| {
                    ui.set_max_width(240.0);

                    // Define a unique ID for focus and state tracking
                    let edit_id = ui.make_persistent_id("timezone_search_input");

                    // Add the text edit widget
                    ui.add(
                        egui::TextEdit::singleline(&mut state.timezone_input)
                            .hint_text("Search...")
                            .id(edit_id),
                    );

                    // Handle Auto-focus & Auto-select on initial open
                    if ui.memory(|m| m.focused().is_none()) {
                        ui.memory_mut(|m| m.request_focus(edit_id));
                    }

                    ui.separator();

                    // List with filtering
                    let filter = state.timezone_input.to_lowercase();
                    for tz in TZ_VARIANTS {
                        let tz_str = tz.to_string();
                        if filter.is_empty() || tz_str.to_lowercase().contains(&filter) {
                            if ui
                                .selectable_label(state.timezone_input == tz_str, &tz_str)
                                .clicked()
                            {
                                state.timezone_input = tz_str;
                                // Manually close the popup
                                ui.close();
                            }
                        }
                    }
                });

            // The returned response's changed() method does not work properly here
            if initial_selected != state.timezone_input {
                let result = validate_timezone(&state.timezone_input);
                if result.is_ok() {
                    state.timezone_validation.set_ok();
                } else {
                    state.timezone_validation.set_err(result.err().unwrap());
                }
            }
        }
    });

    ui.add_space(10.0);

    ui.horizontal(|ui| {
        ui.label("Seed (optional)");

        let response = ui.add(
            egui::TextEdit::singleline(&mut state.seed_input)
                .hint_text("leave empty for random")
                .desired_width(160.0),
        );

        if response.changed() {
            // Convert String to Option<u64>
            match validate_optional_u64(&state.seed_input) {
                Ok(_) => {
                    state.seed_validation.set_ok();
                }
                Err(msg) => {
                    state.seed_validation.set_err(msg);
                }
            }
        }

        show_field_error(ui, &state.seed_validation);
    });

    ui.add_space(15.0);

    ui.checkbox(&mut state.taint, "Taint the packets");

    ui.checkbox(&mut state.order_pcap, "Order temporally");

    ui.add_space(20.0);

    show_status(ui, &state.status);
    if let Some((name, spec, err)) = first_invalid_param(state) {
        ui.colored_label(
            egui::Color32::RED,
            format!("Invalid parameter: {name}. Expected: {spec}. ({err})"),
        );
        ui.add_space(8.0);
    }
    ui.add_space(8.0);

    let can_generate = first_invalid_param(&state).is_none();

    ui.add_enabled_ui(can_generate, |ui| {
        if ui.button("Generate").clicked() {
            state.status = UiStatus::Generating;

            // Reset the progress value
            state.progress = 0.0;

            let (progress_sender, progress_receiver) = channel();
            state.progress_receiver = Some(progress_receiver);

            let (pcap_sender, pcap_receiver) = channel();
            state.pcap_receiver = Some(pcap_receiver);

            let seed = state.seed_input.parse::<u64>().ok();
            let order_pcap = state.order_pcap;
            let start_time = Some(format!(
                "{}T{}Z",
                state.start_date.format("%Y-%m-%d"),
                state.start_hour
            ));
            let duration = state.duration_str.clone();
            let taint = state.taint;
            let timezone = if state.timezone_input.is_empty() {
                None
            } else {
                Some(state.timezone_input.clone())
            };
            let ctx = ui.ctx().clone();
            let file_handle = state.picked_config_file.clone();

            #[cfg(target_arch = "wasm32")]
            {
                wasm_bindgen_futures::spawn_local(async move {
                    let profile = if let Some(file) = file_handle.as_ref() {
                        Some(read_config_file_wasm(file).await)
                    } else {
                        None
                    };
                    generate(
                        seed,
                        profile,
                        order_pcap,
                        start_time,
                        duration,
                        taint,
                        timezone,
                        Some(progress_sender),
                        Some(pcap_sender),
                    );
                    ctx.request_repaint();
                });
            }

            #[cfg(not(target_arch = "wasm32"))]
            {
                std::thread::spawn(move || {
                    let profile = file_handle
                        .as_ref()
                        .map(|file| read_config_file_desktop(file));
                    generate(
                        seed,
                        profile,
                        order_pcap,
                        start_time,
                        duration,
                        taint,
                        timezone,
                        Some(progress_sender),
                        Some(pcap_sender),
                    );
                    ctx.request_repaint();
                });
            }
        }

        if let Some(receiver) = &state.progress_receiver {
            if let Ok(progress) = receiver.try_recv() {
                state.progress = progress;
                // Remove the progress receiver if the generation is done
                if progress >= 1.0 {
                    state.progress_receiver = None;
                }
            }
        }

        if let Some(receiver) = &state.pcap_receiver {
            if let Ok(pcap_bytes) = receiver.try_recv() {
                state.pcap_bytes = Some(pcap_bytes);
            }
        }

        if state.pcap_bytes.is_some() && state.progress == 1.0 {
            state.status = UiStatus::Generated;
            #[cfg(not(target_arch = "wasm32"))]
            let save_button_label = "Save";
            #[cfg(target_arch = "wasm32")]
            let save_button_label = "Download";
            if ui.button(save_button_label).clicked() {
                // --- Save file ---
                let pcap_bytes = state.pcap_bytes.clone();
                #[cfg(not(target_arch = "wasm32"))]
                {
                    let data = pcap_bytes.as_ref().unwrap().as_slice();
                    match save_file_desktop(data, &state.output_file_name) {
                        Ok(file_handle) => {
                            log::info!(
                                "Successfully wrote to file: {}",
                                file_handle.path().to_string_lossy()
                            );
                            state.status = UiStatus::Saved(format!(
                                "Saved to: {}",
                                file_handle.path().to_string_lossy()
                            ));
                        }
                        Err(e) => {
                            log::error!("Failed to save file: {:?}", e);
                            state.status = UiStatus::Error(format!("Failed to save file: {e}"));
                        }
                    }
                }

                #[cfg(target_arch = "wasm32")]
                {
                    // Spawn a local async task to run the file write operation.
                    let file_name = state.output_file_name.clone();
                    wasm_bindgen_futures::spawn_local(async move {
                        let data = pcap_bytes.as_ref().unwrap().as_slice();
                        log::info!("Attempting to write file on WASM...");
                        // Perform the asynchronous write operation. This triggers the browser's saving dialog.
                        match save_file_wasm(data, &file_name).await {
                            Ok(_) => {
                                log::info!("File written successfully!");
                            }
                            Err(e) => {
                                log::error!("Failed to write file: {:?}", e);
                            }
                        }
                    });
                }
            }
        }
    });

    ui.add_space(10.0);

    let progress = egui::ProgressBar::new(state.progress)
        .text("")
        .fill(egui::Color32::from_rgb(144, 238, 144));

    ui.add_sized([ui.available_width(), 20.0], progress);
}
