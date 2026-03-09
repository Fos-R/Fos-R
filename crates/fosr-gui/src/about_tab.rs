use eframe::egui;

pub fn show_about_tab_content(ui: &mut egui::Ui) {
    ui.vertical_centered(|ui| {
        ui.add(egui::Image::new(egui::include_image!("../../../public/logo.png")).max_width(450.0));
    });
    ui.separator();
    ui.add_space(10.0);

    ui.heading("Fos-R - Synthetic Network Traffic Generator");
    ui.add_space(5.0);

    ui.label(
        "Fos-R is a high-quality and high-throughput network traffic generator based on AI models.",
    );
    ui.add_space(15.0);

    ui.heading("Usage Guide");
    ui.add_space(5.0);

    ui.label("This GUI helps you design a Fos-R network configuration visually and generate synthetic network traffic as PCAP files. The Live Preview gives you immediate feedback on your topology before generating. Use the CLI to inject this traffic into a real network.");
    ui.add_space(10.0);

    ui.label(egui::RichText::new("Live Preview").strong());
    ui.label("Visualize what Fos-R would generate based on your configuration. This is a real-time simulation, not the actual generation. Use it to quickly verify your network topology. Click on a node to adjust some properties.");
    ui.add_space(8.0);

    ui.label(egui::RichText::new("Configuration").strong());
    ui.label("Define your network: hosts, their interfaces, and the services they provide. Create a configuration from a template or import an existing YAML file. Switch between visual editing and raw YAML at any time.");
    ui.add_space(8.0);

    ui.label(egui::RichText::new("Generation").strong());
    ui.label("Generate the PCAP file from your configuration. Set parameters like duration and start time. For reproducible results, use a fixed seed. On desktop, open the result in Wireshark to take a quick look.");
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
