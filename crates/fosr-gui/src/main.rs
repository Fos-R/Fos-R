//! Entry point for the Fos-R GUI application.
//! Compiles natively for desktop; delegates to lib.rs for WASM builds.

mod about_tab;
mod app;
mod config_editor;
mod config_templates;
mod run;
mod shared;
mod timepicker;

// Desktop: native compilation
#[cfg(not(target_arch = "wasm32"))]
fn main() -> eframe::Result {
    use crate::app::FosrApp;
    use crate::shared::constants::ui::{
        WINDOW_DEFAULT_HEIGHT, WINDOW_DEFAULT_WIDTH, WINDOW_MIN_HEIGHT, WINDOW_MIN_WIDTH,
    };
    use eframe::egui;
    use env_logger;

    // Redirect log messages to the console
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let shared_viewport = egui::ViewportBuilder::default()
        .with_inner_size([WINDOW_DEFAULT_WIDTH, WINDOW_DEFAULT_HEIGHT])
        .with_min_inner_size([WINDOW_MIN_WIDTH, WINDOW_MIN_HEIGHT])
        .with_title("Fos-R");

    #[cfg(target_os = "macos")]
    let viewport = shared_viewport.with_icon(
        eframe::icon_data::from_png_bytes(&include_bytes!("../assets/fosr-gui-macos.png")[..])
            .expect("Failed to load icon"),
    );

    #[cfg(not(target_os = "macos"))]
    let viewport = shared_viewport.with_icon(
        eframe::icon_data::from_png_bytes(&include_bytes!("../assets/fosr-gui.png")[..])
            .expect("Failed to load icon"),
    );

    let native_options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };
    eframe::run_native(
        "Fos-R GUI",
        native_options,
        Box::new(|cc| {
            egui_material_icons::initialize(&cc.egui_ctx);
            Ok(Box::new(FosrApp::default()))
        }),
    )
}

// Web: empty main, actual code is in lib.rs
#[cfg(target_arch = "wasm32")]
fn main() {
    // lib.rs is used for WASM builds
}
