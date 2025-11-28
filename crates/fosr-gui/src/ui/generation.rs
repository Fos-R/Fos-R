use crate::ui::generate::Params;
use eframe::egui;
use eframe::egui::{SliderClamping, Widget};
use rfd::FileHandle;
use std::io::Error;
use std::time::Duration;

// WASM-specific imports
#[cfg(target_arch = "wasm32")]
use std::sync::mpsc::{channel, Receiver};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_futures;

// Time interval for the slider.
const DURATION_MIN: Duration = Duration::from_secs(60); // 1 min
const DURATION_MAX: Duration = Duration::from_secs(3 * 24 * 3600); // 3 days

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
    let v = if denominator == 0.0 { 0.0 } else { numerator / denominator };
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
fn slider_from_duration_string(duration_str: String) -> f32 {
    let duration = humantime::parse_duration(&duration_str).unwrap();
    duration_to_slider(duration)
}

/**
 * Represents the state of the generation tab.
 */
pub struct GenerationState {
    // --- Files ---
    pub picked_config_file: Option<FileHandle>,
    #[cfg(target_arch = "wasm32")]
    pub config_file_receiver: Option<Receiver<Option<FileHandle>>>,
    pub duration_slider_value: f32,
    pub params: Params,
}

impl Default for GenerationState {
    fn default() -> Self {
        let default_duration = "1h".to_string();
        let default_start_time = "2025-01-01T00:00:00Z".to_string();
        let default_outfile = "output.pcap".to_string();
        let duration_slider_value = slider_from_duration_string(default_duration.clone());

        let mut params = Params::default();
        params.outfile = default_outfile.clone();
        params.order_pcap = false;
        params.start_time = default_start_time.clone();
        params.duration = default_duration.clone();
        params.taint = false;

        Self {
            picked_config_file: None,
            #[cfg(target_arch = "wasm32")]
            config_file_receiver: None,
            duration_slider_value,
            params,
        }
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
fn save_file_desktop(data: &[u8], file_name: &str) -> Result<FileHandle, Error> {
    let result = rfd::FileDialog::new()
        .set_directory(std::env::current_dir().unwrap_or(std::path::PathBuf::from("/")))
        .set_file_name(file_name)
        .save_file()
        .map(|path| FileHandle::from(path));

    match result {
        Some(file_handle) => {
            match std::fs::write(file_handle.path(), data) {
                Ok(_) => Ok(file_handle),
                Err(e) => Err(e),
            }
        }
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
        Some(file_handle) => {
            match file_handle.write(data).await {
                Ok(_) => Ok(file_handle),
                Err(e) => Err(e),
            }
        }
        None => Err(std::io::Error::new(std::io::ErrorKind::Other, "No file selected")),
    }
}


pub fn show_generation_tab_content(ui: &mut egui::Ui, state: &mut GenerationState) {
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
        let filename = state.picked_config_file
            .as_ref()
            .map(|file| file.file_name())
            .unwrap_or("No file selected".to_string());

        // On desktop: filename with its full path on hover, on WASM: just the filename
        #[cfg(not(target_arch = "wasm32"))]
        {
            let path_text = state.picked_config_file
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
            egui::TextEdit::singleline(&mut state.params.outfile)
                .desired_width(200.0)
                .ui(ui);
        });

        ui.separator();
    }

    ui.horizontal(|ui| {
        ui.label("Duration");

        let response = egui::TextEdit::singleline(&mut state.params.duration)
            .desired_width(120.0)
            .ui(ui);

        if response.changed() {
            state.duration_slider_value = slider_from_duration_string(state.params.duration.clone());
        }
    });

    ui.horizontal(|ui| {
        ui.set_width(300.0);
        let response = ui.add(
            egui::Slider::new(&mut state.duration_slider_value, 0.0..=1.0)
                .show_value(false)
                .clamping(SliderClamping::Never),
        );

        if response.changed() {
            state.params.duration = duration_string_from_slider(state.duration_slider_value);
        }
    });

    ui.add_space(10.0);

    ui.horizontal(|ui| {
        ui.label("Start time");

        egui::TextEdit::singleline(&mut state.params.start_time)
            .desired_width(150.0)
            .ui(ui);
    });

    ui.add_space(15.0);

    ui.checkbox(&mut state.params.taint, "Taint the packets");
    ui.checkbox(&mut state.params.order_pcap, "Order temporally");

    ui.add_space(20.0);

    ui.horizontal(|ui| {
        if ui.button("Generate").clicked() {
            println!(
                "Generate button clicked with params: {:?}",
                state.params
            );

            // state.duration_input = "1h".to_string();
            // state.order_temporally = false;
            // state.start_time = "2025-01-01T00:00:00Z".to_string();
            // state.taint_packets = false;

            // state.params = Params {
            //      seed: None,
            //      profile: None,
            //      outfile: "output.pcap".to_string(),
            //      packets_count: None,
            //      order_pcap: state.order_temporally,
            //      start_time: Some(state.start_time.clone()),
            //      duration: Some(state.duration_input.clone()),
            //      taint: state.taint_packets,
            //  };
            //
            //  generate(
            //      state.params.seed,
            //      state.params.profile.clone(),
            //      state.params.outfile.clone(),
            //      state.params.packets_count,
            //      state.params.order_pcap,
            //      state.params.start_time.clone(),
            //      state.params.duration.clone(),
            //      state.params.taint,
            //  );
        }

        #[cfg(not(target_arch = "wasm32"))]
        let save_button_label = "Save";
        #[cfg(target_arch = "wasm32")]
        let save_button_label = "Download";
        if ui.button(save_button_label).clicked() {
            // --- Save file ---
            let data = "Hello world!\nThis text was written by the Fos-R app.";

            #[cfg(not(target_arch = "wasm32"))]
            {
                match save_file_desktop(data.as_bytes(), &state.params.outfile) {
                    Ok(file_handle) => {
                        println!("Successfully wrote to file: {}", file_handle.path().to_string_lossy());
                    }
                    Err(e) => {
                        eprintln!("Failed to save file: {:?}", e);
                    }
                }
            }

            #[cfg(target_arch = "wasm32")]
            {
                // Spawn a local async task to run the file write operation.
                let file_name = state.params.outfile.clone();
                wasm_bindgen_futures::spawn_local(async move {
                    println!("Attempting to write file on WASM...");
                    // Perform the asynchronous write operation. This triggers the browser's saving dialog.
                    match save_file_wasm(data.as_bytes(), &file_name).await {
                        Ok(_) => {
                            println!("File written successfully!");
                        }
                        Err(e) => {
                            eprintln!("Failed to write file: {:?}", e);
                        }
                    }
                });
            }
        }
    });

    ui.add_space(10.0);

    let progress = egui::ProgressBar::new(0.5)
        .text("")
        .fill(egui::Color32::from_rgb(144, 238, 144));

    ui.add_sized([ui.available_width(), 20.0], progress);
}
