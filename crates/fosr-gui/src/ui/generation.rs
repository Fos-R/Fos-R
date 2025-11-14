use eframe::egui;
use eframe::egui::{SliderClamping, Widget};
use rfd::FileHandle;
#[cfg(target_arch = "wasm32")]
use std::sync::mpsc::{channel, Receiver};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_futures;


#[derive(Default)]
pub struct GenerationState {
    pub picked_config_file: Option<FileHandle>,
    #[cfg(target_arch = "wasm32")]
    pub file_receiver: Option<Receiver<Option<FileHandle>>>,
    pub taint_packets: bool,
    pub order_temporally: bool,
    pub start_time: String,
    /*
        Those two should be linked: if we edit the duration text input, it should be
        parsed as a timestamp, and update the slider value; if we move the slider,
        we should convert it to a String representation and update the text input.
     */
    pub duration_input: String,
    pub duration_slider_value: f32,
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

pub fn show_generation_tab_content(ui: &mut egui::Ui, state: &mut GenerationState) {
    ui.add_space(5.0);

    ui.horizontal(|ui| {
        ui.label("Configuration file:");

        // File Dialog to pick config file
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
                state.file_receiver = Some(receiver);

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
            if let Some(receiver) = &state.file_receiver {
                if let Ok(file) = receiver.try_recv() {
                    // Only update if a file was actually selected
                    if file.is_some() {
                        state.picked_config_file = file;
                    }
                    state.file_receiver = None;
                }
            }
        }

        // Display the filename of the picked file, or a placeholder
        let filename = state.picked_config_file
            .as_ref()
            .map(|file| file.file_name())
            .unwrap_or("No file selected".to_string());

        // On desktop: filename with full path on hover, on WASM: just the filename
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

    ui.horizontal(|ui| {
        ui.label("Duration");

        egui::TextEdit::singleline(&mut state.duration_input)
            .desired_width(120.0)
            .ui(ui);
    });

    ui.horizontal(|ui| {
        ui.set_width(300.0);
        ui.add(
            egui::Slider::new(&mut state.duration_slider_value, 0.0..=1.0)
                .show_value(false)
                .clamping(SliderClamping::Never),
        );
    });

    ui.add_space(10.0);

    ui.horizontal(|ui| {
        ui.label("Start time");

        egui::TextEdit::singleline(&mut state.start_time)
            .desired_width(150.0)
            .ui(ui);
    });

    ui.add_space(15.0);

    ui.checkbox(&mut state.taint_packets, "Taint the packets");
    ui.checkbox(&mut state.order_temporally, "Order temporally");

    ui.add_space(20.0);

    ui.horizontal(|ui| {
        if ui.button("Generate").clicked() {
            println!(
                "Generate button clicked with duration: {}",
                state.duration_input
            );
        }

        if ui.button("Download").clicked() {
            println!("Download button clicked!");
        }
    });

    ui.add_space(10.0);

    let progress = egui::ProgressBar::new(0.5)
        .text("")
        .fill(egui::Color32::from_rgb(144, 238, 144));

    ui.add_sized([ui.available_width(), 20.0], progress);
}
