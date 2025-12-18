use eframe::egui;

pub fn show_about_tab_content(ui: &mut egui::Ui) {
    ui.image(egui::include_image!("../../../public/logo.png"));
    ui.separator();
    ui.add_space(10.0);

    ui.heading("Fos-R - Synthetic Network Traffic Generator");
    ui.add_space(5.0);

    ui.label(
        "Fos-R is a high-quality and high-throughput network traffic generator based on AI models.",
    );
    ui.add_space(15.0);

    ui.heading("Repository Information");
    ui.add_space(5.0);
    ui.horizontal(|ui| {
        ui.label("GitLab - Main repository:");
        ui.hyperlink("https://gitlab.inria.fr/pirat-public/Fos-R");
    });
    ui.add_space(5.0);
    ui.horizontal(|ui| {
        ui.label("GitHub mirror:");
        ui.hyperlink("https://github.com/Fos-R/Fos-R");
    });
    ui.add_space(5.0);
    ui.horizontal(|ui| {
        ui.label("Website:");
        ui.hyperlink("https://fosr.inria.fr");
    });
    ui.add_space(15.0);

    ui.heading("Contact");
    ui.add_space(5.0);
    ui.horizontal(|ui| {
        ui.label("Maintainer:");
        ui.hyperlink_to(
            "pierre-francois.gimenez@inria.fr",
            "mailto:pierre-francois.gimenez@inria.fr",
        );
    });
}
