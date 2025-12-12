#![cfg(not(target_arch = "wasm32"))]
use eframe::egui;

pub fn show_injection_tab_content(ui: &mut egui::Ui) {
    ui.heading("You are on the Injection Tab");
    ui.separator();
    if ui.button("Inject traffic").clicked() {
        // Add logic here
    }
}
