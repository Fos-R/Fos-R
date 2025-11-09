use eframe::egui;

pub fn show_generation_tab_content(ui: &mut egui::Ui) {
    ui.heading("You are on the Generation Tab");
    ui.separator();
    if ui.button("Generate a pcap").clicked() {
        // Add logic here
    }
}
