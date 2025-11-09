use eframe::egui;

pub fn show_about_tab_content(ui: &mut egui::Ui) {
    ui.heading("You are on the About Tab");
    ui.separator();
    ui.hyperlink("https://github.com/Fos-R/Fos-R");
}
