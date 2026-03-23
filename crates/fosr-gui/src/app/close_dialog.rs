//! Close confirmation dialog for desktop when Wireshark sessions are active.

use crate::shared::constants::ui::{MODAL_WIDTH_SM, SPACING_LG, SPACING_XL};
use eframe::egui;

/// Render the close confirmation dialog if needed.
pub fn render_close_confirmation_dialog(
    ctx: &egui::Context,
    show_dialog: &mut bool,
    allowed_to_close: &mut bool,
) {
    if !*show_dialog {
        return;
    }

    egui::Modal::new(egui::Id::new("close_confirmation_modal")).show(ctx, |ui| {
        ui.set_width(MODAL_WIDTH_SM);
        ui.heading("Confirm Exit");
        ui.add_space(SPACING_LG);
        ui.label("You have Wireshark session(s) open with temporary PCAP files.");
        ui.label("Closing will delete these files.");
        ui.add_space(SPACING_XL);
        ui.horizontal(|ui| {
            if ui.button("Cancel").clicked() {
                *show_dialog = false;
            }
            if ui.button("Exit").clicked() {
                *show_dialog = false;
                *allowed_to_close = true;
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        });
    });
}
