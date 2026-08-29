//! About tab: Fos-R information, usage guide, and repository links.

use crate::shared::assets::*;
use crate::shared::constants::ui::{
    LOGO_MAX_HEIGHT, SPACING_SM, SPACING_XXL,
};
use eframe::egui;

/// Renders the About modal with application info and repository links.
pub fn render_about_modal(ui: &mut egui::Ui) {
    ui.columns(2, |cols| {
    cols[1].add(egui::Image::new(IMG_LOGO));
    cols[0].heading("Fos-R - Synthetic Traffic Generator");
    cols[0].label(
        "Fos-R is a high-quality, high-throughput, ML-based network traffic generator under GPL-3.0 license",
    );
    });
    ui.separator();

    ui.columns(2, |cols| {
        cols[0].horizontal(|ui| {
            ui.label("Website:");
            ui.hyperlink("https://fosr.inria.fr");
        });

        cols[1].horizontal(|ui| {
            ui.label("Repository:");
            ui.hyperlink_to("GitLab", "https://gitlab.inria.fr/pirat-public/Fos-R");
            ui.label("–");
            ui.hyperlink_to("GitHub Mirror", "https://github.com/Fos-R/Fos-R");
        });
    });
    ui.add_space(SPACING_SM);
    // ui.add_space(SPACING_SM);
    // ui.horizontal(|ui| {
    //     ui.label("GitHub mirror:");
    //     ui.hyperlink("https://github.com/Fos-R/Fos-R");
    // });
    // ui.add_space(SPACING_XXL);

    ui.horizontal(|ui| {
        ui.label("Maintainer:");
        ui.hyperlink_to(
            "pierre-francois.gimenez@inria.fr",
            "mailto:pierre-francois.gimenez@inria.fr",
        );
    });
    ui.add_space(SPACING_SM);
    ui.label("Contributors: Pierre-François Gimenez (Inria), Adrien Schoen (Inria), Pol Jaouen (Inria), Lénaïg Cornanguer (CISPA), Joscha Cüppers (CISPA), Dorian Bachelot (CentraleSupélec), Evan Morin (CentraleSupélec), Florentin Labelle (CentraleSupélec), Samuel Cordon (CentraleSupélec), Quentin Blin (CentraleSupélec)");

    ui.add_space(SPACING_XXL);

    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        ui.label("Fos-R originates from research carried out by the ");
        ui.hyperlink_to("PIRAT\\');", "https://team.inria.fr/pirat/");
        ui.label(" research team and is supported by ");
        ui.hyperlink_to("Inria", "https://www.inria.fr/");
        ui.label(".");
    });
    ui.add_space(SPACING_SM);
    ui.columns(2, |cols| {
        cols[0].vertical_centered(|ui| {
            ui.add(egui::Image::new(IMG_LOGO_PIRAT).max_height(LOGO_MAX_HEIGHT));
        });
        cols[1].vertical_centered(|ui| {
            ui.add(egui::Image::new(IMG_LOGO_INRIA).max_height(LOGO_MAX_HEIGHT));
        });
    });
    ui.add_space(SPACING_SM);
}
