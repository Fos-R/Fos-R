mod app;
mod ui;

// Desktop: native compilation
#[cfg(not(target_arch = "wasm32"))]
fn main() -> eframe::Result {
    use crate::app::FosrApp;
    use eframe::egui;
    use env_logger;

    // Redirect log messages to the console
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([500.0, 440.0])
            .with_min_inner_size([400.0, 350.0])
            .with_title("Fos-R")
            .with_icon(
                eframe::icon_data::from_png_bytes(&include_bytes!("../../../public/fosr.png")[..])
                    .expect("Failed to load icon"),
            ),
        ..Default::default()
    };
    eframe::run_native(
        "Fos-R GUI",
        native_options,
        Box::new(|_cc| Ok(Box::new(FosrApp::default()))),
    )
}

// Web: empty main, actual code is in lib.rs
#[cfg(target_arch = "wasm32")]
fn main() {
    // lib.rs is used for WASM builds
}
