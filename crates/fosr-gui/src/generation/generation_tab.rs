use super::generation_core::generate;
use super::generation_ui_components::{show_field_error, show_status, timezone_picker};
use super::generation_validation::{
    FieldValidation, first_invalid_param, validate_duration, validate_optional_u64,
    validate_timezone,
};
use crate::shared::configuration_file::{ConfigurationFileState, load_config_file_contents};
#[cfg(not(target_arch = "wasm32"))]
use crate::shared::file_io::save_file_desktop;
#[cfg(target_arch = "wasm32")]
use crate::shared::file_io::save_file_wasm;
use crate::shared::ui_utils::info_icon;
use crate::timepicker::TimePickerButton;
use chrono::{Datelike, Local, NaiveDate, NaiveTime, TimeZone};
use chrono_tz::Tz;
use eframe::egui;
use eframe::egui::Widget;
use egui_extras::DatePickerButton;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;

// Time interval for the slider.
pub const DURATION_MIN: Duration = Duration::from_secs(60); // 1 min
#[cfg(not(target_arch = "wasm32"))]
pub const DURATION_MAX: Duration = Duration::from_secs(3 * 24 * 3600); // 3 days
#[cfg(target_arch = "wasm32")]
pub const DURATION_MAX: Duration = Duration::from_secs(24 * 3600); // 1 day (browser tab memory is limited)

pub enum UiStatus {
    Idle,
    Generating,
    Generated,
    #[cfg(not(target_arch = "wasm32"))]
    Saved(String),
    #[cfg(not(target_arch = "wasm32"))]
    Error(String),
}

/// Represents the state of the generation tab.
pub struct GenerationTabState {
    pub progress: f32,
    pub progress_receiver: Option<Receiver<f32>>,
    pub pcap_bytes: Option<Vec<u8>>,
    pub pcap_receiver: Option<Receiver<Vec<u8>>>,
    pub throughput_receiver: Option<Receiver<String>>,
    pub throughput: Option<String>,
    pub cancelled: Arc<AtomicBool>,
    pub status: UiStatus,
    // Validation states
    pub duration_validation: FieldValidation,
    pub seed_validation: FieldValidation,
    pub timezone_validation: FieldValidation,
    // Parameters
    pub order_pcap: bool,
    pub taint: bool,
    pub duration_str: String,
    pub use_seed: bool,
    pub seed_input: String,
    pub timezone_input: String,
    pub use_current_time: bool,
    pub use_local_timezone: bool,
    pub start_date: NaiveDate,
    pub start_hour: NaiveTime,
    pub output_file_name: String,
    /// Holds the temporary PCAP file opened in Wireshark.
    ///
    /// `NamedTempFile` automatically deletes the file when dropped. By storing it here,
    /// the file stays alive until: (1) the app closes, or (2) a new file is opened
    /// (which replaces this value, dropping the previous file).
    #[cfg(not(target_arch = "wasm32"))]
    pub temp_pcap_file: Option<tempfile::NamedTempFile>,
}

impl Default for GenerationTabState {
    fn default() -> Self {
        Self {
            progress: 0.0,
            progress_receiver: None,
            pcap_bytes: None,
            pcap_receiver: None,
            throughput_receiver: None,
            throughput: None,
            cancelled: Arc::new(AtomicBool::new(false)),
            status: UiStatus::Idle,
            // Validation states
            duration_validation: FieldValidation::default(),
            seed_validation: FieldValidation::default(),
            timezone_validation: FieldValidation::default(),
            // Parameters
            order_pcap: true,
            taint: false,
            duration_str: "1h".to_string(),
            use_seed: false,
            seed_input: String::new(),
            timezone_input: String::new(),
            use_current_time: true,
            use_local_timezone: true,
            start_date: Local::now().date_naive(),
            start_hour: Local::now().time(),
            output_file_name: "output.pcap".to_string(),
            #[cfg(not(target_arch = "wasm32"))]
            temp_pcap_file: None,
        }
    }
}

pub fn show_generation_tab_content(
    ui: &mut egui::Ui,
    state: &mut GenerationTabState,
    configuration_file_state: &mut ConfigurationFileState,
) {
    // Eagerly load config file contents when a file is selected
    load_config_file_contents(configuration_file_state);

    ui.horizontal(|ui| {
        ui.label("Duration");
        info_icon(ui, "Minimum pcap traffic duration described in human-friendly time, such as \"30m\", \"1h\", \"2d\" or \"2days 30min 5s\".");

        // Preset buttons
        for preset in ["5min", "1h", "24h"] {
            if ui.small_button(preset).clicked() {
                state.duration_str = preset.to_string();
                state.duration_validation.set_ok();
            }
        }

        let text_response = egui::TextEdit::singleline(&mut state.duration_str)
            .desired_width(100.0)
            .hint_text("ex: 30m, 1h, 2d")
            .ui(ui);

        if text_response.changed() {
            match validate_duration(&state.duration_str) {
                Ok(_) => {
                    state.duration_validation.set_ok();
                }
                Err(msg) => {
                    state.duration_validation.set_err(msg);
                }
            }
        }

        show_field_error(ui, &state.duration_validation);
    });

    ui.add_space(10.0);

    ui.horizontal(|ui| {
        ui.checkbox(&mut state.use_current_time, "Use current time for start time");
        info_icon(ui, "Beginning time of the pcap. By default, use the current time. For deterministic generation, you must specify this along with duration, timezone and seed.");
    });

    if !state.use_current_time {
        ui.horizontal(|ui| {
            ui.label("Start time");
            let current_year = Local::now().date_naive().year();
            ui.add(
                DatePickerButton::new(&mut state.start_date)
                    .start_end_years((current_year - 5)..=(current_year + 30)),
            );
            ui.add(
                TimePickerButton::new(&mut state.start_hour)
                    .show_seconds(true)
                    .use_dragvalue(true),
            );
        });

        ui.add_space(10.0);

        ui.horizontal(|ui| {
            if ui
                .checkbox(&mut state.use_local_timezone, "Use local timezone")
                .clicked()
            {
                if state.use_local_timezone {
                    state.timezone_input = String::new();
                    state.timezone_validation.set_ok();
                } else {
                    state.timezone_input = Tz::CET.to_string();
                }
            }
            info_icon(ui, "Timezone used for realistic work hours. Use an IANA time zone (like Europe/Paris) or an abbreviation (like CET). The offset is assumed constant during the generation time range.");
            if !state.use_local_timezone {
                timezone_picker(ui, state);

                let result = validate_timezone(&state.timezone_input);
                if result.is_ok() {
                    state.timezone_validation.set_ok();
                } else {
                    state.timezone_validation.set_err(result.err().unwrap());
                }
            }
        });
    } else {
        state.timezone_validation.set_ok();
    }

    // Show the equivalent UTC start time
    let utc_label = if state.use_current_time {
        Some(chrono::Utc::now())
    } else {
        let local_dt = state.start_date.and_time(state.start_hour);
        if state.use_local_timezone {
            Local::now()
                .timezone()
                .from_local_datetime(&local_dt)
                .earliest()
                .map(|dt| dt.with_timezone(&chrono::Utc))
        } else {
            state
                .timezone_input
                .parse::<Tz>()
                .ok()
                .and_then(|tz| local_dt.and_local_timezone(tz).earliest())
                .map(|dt| dt.with_timezone(&chrono::Utc))
        }
    };
    if let Some(utc) = utc_label {
        ui.label(
            egui::RichText::new(format!(
                "Start time (UTC): {}",
                utc.format("%Y-%m-%d %H:%M:%S")
            ))
            .color(egui::Color32::GRAY),
        );
    }

    ui.add_space(10.0);

    ui.horizontal(|ui| {
        ui.checkbox(&mut state.use_seed, "Seed");
        info_icon(ui, "Seed for random number generation. For deterministic generation, you must also specify duration, start time, and timezone.");

        if state.use_seed {
            let response = ui.add(
                egui::TextEdit::singleline(&mut state.seed_input)
                    .hint_text("enter a seed value")
                    .desired_width(160.0),
            );

            if response.changed() {
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
        } else {
            state.seed_validation.set_ok();
        }
    });

    ui.add_space(15.0);

    ui.horizontal(|ui| {
        ui.checkbox(&mut state.taint, "Taint the packets");
        info_icon(ui, "Taint the packets with special markers for identification.");
        ui.add_space(10.0);
        ui.checkbox(&mut state.order_pcap, "Order temporally");
        info_icon(ui, "Enable temporal sorting of the generated pcap. Disable to reduce significantly the RAM usage.");
    });

    ui.add_space(20.0);

    let can_generate = first_invalid_param(&state).is_none();
    let is_generating = matches!(state.status, UiStatus::Generating);

    ui.horizontal(|ui| {
        if is_generating {
            let stop_button = egui::Button::new(
                egui::RichText::new(format!("{} Stop", egui_material_icons::icons::ICON_STOP))
                    .size(13.0),
            )
            .fill(egui::Color32::from_rgb(200, 80, 80))
            .min_size(egui::vec2(75.0, 24.0));
            if ui
                .add(stop_button)
                .on_hover_text("Cancel generation")
                .clicked()
            {
                state.cancelled.store(true, Ordering::Relaxed);
                state.status = UiStatus::Idle;
                state.progress = 0.0;
                state.progress_receiver = None;
                state.pcap_receiver = None;
                state.throughput_receiver = None;
            }
        }

        if !is_generating {
            ui.add_enabled_ui(can_generate, |ui| {
                let accent = ui.visuals().selection.bg_fill;
                let generate_button = egui::Button::new(
                    egui::RichText::new(format!(
                        "{} Generate",
                        egui_material_icons::icons::ICON_PLAY_ARROW
                    ))
                    .size(13.0),
                )
                .fill(accent)
                .min_size(egui::vec2(85.0, 24.0));
                if ui
                    .add(generate_button)
                    .on_hover_text("Generate PCAP from configuration")
                    .clicked()
                {
                    state.status = UiStatus::Generating;

                    // Reset state
                    state.progress = 0.0;
                    state.cancelled = Arc::new(AtomicBool::new(false));

                    let (progress_sender, progress_receiver) = channel();
                    state.progress_receiver = Some(progress_receiver);

                    let (pcap_sender, pcap_receiver) = channel();
                    state.pcap_receiver = Some(pcap_receiver);

                    let (throughput_sender, throughput_receiver) = channel();
                    state.throughput_receiver = Some(throughput_receiver);
                    state.throughput = None;

                    let seed = if state.use_seed {
                        state.seed_input.parse::<u64>().ok()
                    } else {
                        None
                    };
                    let order_pcap = state.order_pcap;
                    let start_time = if state.use_current_time {
                        None
                    } else {
                        Some(format!(
                            "{}T{}Z",
                            state.start_date.format("%Y-%m-%d"),
                            state.start_hour.format("%H:%M:%S")
                        ))
                    };
                    let duration = state.duration_str.clone();
                    let taint = state.taint;
                    let timezone = if state.timezone_input.is_empty() {
                        None
                    } else {
                        Some(state.timezone_input.clone())
                    };
                    let ctx = ui.ctx().clone();
                    let cancelled = state.cancelled.clone();
                    // Prefer in-memory config content (reflects edits from Configuration tab)
                    // over re-reading the file from disk
                    let config_content = configuration_file_state.config_file_content.clone();

                    #[cfg(target_arch = "wasm32")]
                    {
                        wasm_bindgen_futures::spawn_local(async move {
                            generate(
                                seed,
                                config_content,
                                order_pcap,
                                start_time,
                                duration,
                                taint,
                                timezone,
                                Some(progress_sender),
                                Some(pcap_sender),
                                Some(throughput_sender),
                                cancelled,
                            );
                            ctx.request_repaint();
                        });
                    }

                    #[cfg(not(target_arch = "wasm32"))]
                    {
                        std::thread::spawn(move || {
                            generate(
                                seed,
                                config_content,
                                order_pcap,
                                start_time,
                                duration,
                                taint,
                                timezone,
                                Some(progress_sender),
                                Some(pcap_sender),
                                Some(throughput_sender),
                                cancelled,
                            );
                            ctx.request_repaint();
                        });
                    }
                }
            });
        }

        // Poll receivers (must be outside add_enabled_ui to run while generating)
        if let Some(receiver) = &state.progress_receiver {
            // Request repaint to keep polling while generating
            ui.ctx().request_repaint();
            if let Ok(progress) = receiver.try_recv() {
                state.progress = progress;
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

        if let Some(receiver) = &state.throughput_receiver {
            if let Ok(throughput) = receiver.try_recv() {
                state.throughput = Some(throughput);
                state.throughput_receiver = None;
            }
        }

        if state.pcap_bytes.is_some() && state.progress == 1.0 {
            #[cfg(not(target_arch = "wasm32"))]
            if !matches!(state.status, UiStatus::Saved(_) | UiStatus::Error(_)) {
                state.status = UiStatus::Generated;
            }
            #[cfg(target_arch = "wasm32")]
            {
                state.status = UiStatus::Generated;
            }
            #[cfg(not(target_arch = "wasm32"))]
            let save_button_text = format!("{} Save", egui_material_icons::icons::ICON_SAVE);
            #[cfg(target_arch = "wasm32")]
            let save_button_text =
                format!("{} Download", egui_material_icons::icons::ICON_DOWNLOAD);
            #[cfg(not(target_arch = "wasm32"))]
            let save_button_tooltip = "Save PCAP file";
            #[cfg(target_arch = "wasm32")]
            let save_button_tooltip = "Download PCAP file";
            let save_button = egui::Button::new(egui::RichText::new(save_button_text).size(13.0))
                .min_size(egui::vec2(75.0, 24.0));
            if ui
                .add(save_button)
                .on_hover_text(save_button_tooltip)
                .clicked()
            {
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
                    let file_name = state.output_file_name.clone();
                    wasm_bindgen_futures::spawn_local(async move {
                        let data = pcap_bytes.as_ref().unwrap().as_slice();
                        log::info!("Attempting to write file on WASM...");
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

            // Open in Wireshark button (native only)
            #[cfg(not(target_arch = "wasm32"))]
            {
                let open_button = egui::Button::new(
                    egui::RichText::new(format!("{} Open", egui_material_icons::icons::ICON_LAN))
                        .size(13.0),
                )
                .min_size(egui::vec2(75.0, 24.0));
                if ui
                    .add(open_button)
                    .on_hover_text("Open with default application (e.g. Wireshark)")
                    .clicked()
                {
                    if let Some(ref pcap_bytes) = state.pcap_bytes {
                        match open_in_wireshark(pcap_bytes, &mut state.temp_pcap_file) {
                            Ok(_) => {
                                log::info!("Opened PCAP in Wireshark");
                            }
                            Err(e) => {
                                log::error!("Failed to open in Wireshark: {:?}", e);
                                state.status =
                                    UiStatus::Error(format!("Failed to open in Wireshark: {e}"));
                            }
                        }
                    }
                }
            }
        }
    });

    ui.add_space(10.0);

    if !matches!(state.status, UiStatus::Idle) {
        let progress = egui::ProgressBar::new(state.progress)
            .text("")
            .fill(egui::Color32::from_rgb(144, 238, 144));

        ui.add_sized([ui.available_width(), 20.0], progress);
    }

    show_status(ui, &state.status);

    if let Some(throughput) = &state.throughput {
        ui.label(format!("Throughput: {throughput}"));
    }

    if let Some((name, spec, err)) = first_invalid_param(state) {
        ui.colored_label(
            egui::Color32::RED,
            format!("Invalid parameter: {name}. Expected: {spec}. ({err})"),
        );
    }
}

/// Opens the PCAP data in the system's default application (e.g., Wireshark).
///
/// This creates a temporary file with `.pcap` extension and opens it using `open::that()`.
/// The `NamedTempFile` handle is stored in `temp_file_storage` to keep the file alive.
/// When the handle is dropped (app closes or a new file is opened), the temp file is deleted.
#[cfg(not(target_arch = "wasm32"))]
fn open_in_wireshark(
    pcap_bytes: &[u8],
    temp_file_storage: &mut Option<tempfile::NamedTempFile>,
) -> Result<(), String> {
    use std::io::Write;

    // Create a temporary file with .pcap extension
    let mut temp_file = tempfile::Builder::new()
        .suffix(".pcap")
        .tempfile()
        .map_err(|e| format!("Failed to create temp file: {e}"))?;

    // Write the PCAP data
    temp_file
        .write_all(pcap_bytes)
        .map_err(|e| format!("Failed to write PCAP data: {e}"))?;

    // Get the path
    let path = temp_file.path().to_path_buf();

    log::info!("Opening PCAP file at: {}", path.display());

    // Store the temp file to keep it alive until app closes
    *temp_file_storage = Some(temp_file);

    // Open with system default application (Wireshark for .pcap files)
    open::that(&path).map_err(|e| format!("Failed to open file: {e}"))?;

    Ok(())
}
