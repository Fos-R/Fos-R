//! About tab: Fos-R information, usage guide, and repository links.

use crate::shared::assets::IMG_LOGO;
use crate::shared::constants::ui::{LOGO_MAX_WIDTH, SPACING_LG, SPACING_SM, SPACING_XXL};
use eframe::egui;

/// Renders the About tab with application info, usage guide, and repository links.
pub fn render_about_tab(ui: &mut egui::Ui) {
    ui.vertical_centered(|ui| {
        ui.add(egui::Image::new(IMG_LOGO).max_width(LOGO_MAX_WIDTH));
    });
    ui.separator();
    ui.add_space(SPACING_LG);

    ui.heading("Fos-R - Synthetic Network Traffic Generator");
    ui.add_space(SPACING_SM);

    ui.label(
        "Fos-R is a high-quality and high-throughput network traffic generator based on AI models.",
    );
    ui.add_space(SPACING_XXL);

    ui.heading("Usage Guide");
    ui.add_space(SPACING_SM);

    ui.label("This GUI helps you design a Fos-R network configuration visually and generate synthetic network traffic as PCAP files. Export your configuration to use it with the CLI, which can generate and inject live traffic directly on a network.");
    ui.add_space(SPACING_LG);

    ui.label(egui::RichText::new("Run").strong());
    ui.label("• Live Preview: visualize what Fos-R would generate based on your configuration. This is a real-time simulation, not the actual generation. Use it to quickly verify your network topology. Click on a node to adjust some properties.");
    ui.label("• Generation: generate the PCAP file from your configuration. Set parameters like duration and start time. For reproducible results, use a fixed seed. On desktop, open the result in Wireshark to take a quick look.");
    ui.add_space(SPACING_LG);

    ui.label(egui::RichText::new("Configuration").strong());
    ui.label("Define your network: hosts, their interfaces, and the services they provide. Create a configuration from a template or import an existing YAML file. Switch between visual editing and raw YAML at any time.");
    ui.add_space(SPACING_XXL);

    ui.heading("Repository Information");
    ui.add_space(SPACING_SM);
    ui.horizontal(|ui| {
        ui.label("GitLab - Main repository:");
        ui.hyperlink("https://gitlab.inria.fr/pirat-public/Fos-R");
    });
    ui.add_space(SPACING_SM);
    ui.horizontal(|ui| {
        ui.label("GitHub mirror:");
        ui.hyperlink("https://github.com/Fos-R/Fos-R");
    });
    ui.add_space(SPACING_SM);
    ui.horizontal(|ui| {
        ui.label("Website:");
        ui.hyperlink("https://fosr.inria.fr");
    });
    ui.add_space(SPACING_XXL);

    ui.heading("Contact");
    ui.add_space(SPACING_SM);
    ui.horizontal(|ui| {
        ui.label("Maintainer:");
        ui.hyperlink_to(
            "pierre-francois.gimenez@inria.fr",
            "mailto:pierre-francois.gimenez@inria.fr",
        );
    });
}
