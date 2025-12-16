use super::generation_core::generate;
#[cfg(not(target_arch = "wasm32"))]
use super::generation_io::{read_config_file_desktop, save_file_desktop, show_file_picker_desktop};
#[cfg(target_arch = "wasm32")]
use super::generation_io::{read_config_file_wasm, save_file_wasm, show_file_picker_wasm};
use super::generation_ui_components::{show_field_error, show_status, timezone_picker};
use super::generation_utils::{
    duration_string_from_slider, duration_to_slider, slider_from_duration_string,
};
use super::generation_validation::{
    FieldValidation, first_invalid_param, validate_duration, validate_optional_u64,
    validate_start_hour, validate_timezone,
};
use chrono::NaiveDate;
use chrono_tz::Tz;
use eframe::egui;
use eframe::egui::{SliderClamping, Widget};
use egui_extras::DatePickerButton;
use rfd::FileHandle;
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_futures;

// Time interval for the slider.
pub const DURATION_MIN: Duration = Duration::from_secs(60); // 1 min
pub const DURATION_MAX: Duration = Duration::from_secs(3 * 24 * 3600); // 3 days

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
            timezone_input: String::new(),
            use_local_timezone: true,
            start_date: NaiveDate::from_ymd_opt(2025, 1, 1).unwrap(),
            start_hour: "00:00:00".to_string(),
            output_file_name: "output.pcap".to_string(),
        }
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
        if ui
            .checkbox(&mut state.use_local_timezone, "Use local timezone")
            .clicked()
        {
            if state.use_local_timezone {
                // Reset the timezone
                state.timezone_input = String::new();
                state.timezone_validation.set_ok();
            } else {
                // Set the default timezone
                state.timezone_input = Tz::CET.to_string();
            }
        }
        if !state.use_local_timezone {
            // Display the dropdown button
            timezone_picker(ui, state);

            let result = validate_timezone(&state.timezone_input);
            if result.is_ok() {
                state.timezone_validation.set_ok();
            } else {
                state.timezone_validation.set_err(result.err().unwrap());
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
