#![cfg(target_arch = "wasm32")]
mod about_tab;
mod app;
mod configuration;
mod generation;
#[cfg(not(target_arch = "wasm32"))]
mod injection_tab;
mod shared;
mod timepicker;
mod visualization;

use app::FosrApp;
use eframe::wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub async fn start(canvas_id: &str) -> Result<(), JsValue> {
    // Redirect `log` message to `console.log`:
    eframe::WebLogger::init(log::LevelFilter::Debug).ok();

    let web_options = eframe::WebOptions::default();

    let document = web_sys::window()
        .expect("No window")
        .document()
        .expect("No document");

    // The canvas_id is passed as an argument from the HTML file
    // and identifies the canvas element on which the app will be rendered
    let canvas = document
        .get_element_by_id(canvas_id)
        .expect(format!("Failed to find {}", canvas_id).as_str())
        .dyn_into::<web_sys::HtmlCanvasElement>()
        .expect(format!("{} is not an HtmlCanvasElement", canvas_id).as_str());

    eframe::WebRunner::new()
        .start(
            canvas,
            web_options,
            Box::new(|_cc| Ok(Box::new(FosrApp::default()))),
        )
        .await?;

    Ok(())
}
