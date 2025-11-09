use eframe::egui;
use eframe::egui::{SliderClamping, Widget};

#[derive(Default)]
pub struct GenerationState {
    pub configuration_folder: String,
    pub duration_input: String,
    pub start_time: String,
    pub duration_slider_value: f32,
    pub taint_packets: bool,
    pub order_temporally: bool,
}

pub fn show_generation_tab_content(ui: &mut egui::Ui, state: &mut GenerationState) {
    ui.add_space(5.0);

    ui.horizontal(|ui| {
        ui.label("Configuration folder");
        ui.label(format!(": {}", state.configuration_folder))
            .on_hover_text("Path to the configuration files");

        if ui.button("Select folder").clicked() {
            state.configuration_folder = "C:\\Users\\...\\config".to_string();
            println!("Select folder clicked!");
        }
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
