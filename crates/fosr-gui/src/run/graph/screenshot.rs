//! Graph screenshot export with a 2-frame state machine for clean PNG output.

use super::state::ScreenshotStateMachine;
use super::state::VisualizationState;
use eframe::egui;

/// Handle screenshot export state machine.
/// Uses a 2-frame approach:
/// - Frame N: user clicks export → HidingOverlays
/// - Frame N+1: overlays hidden → request screenshot → WaitingForScreenshot
/// - Frame N+2: screenshot received → extract graph region → save → Idle
pub fn handle_screenshot_export(ui: &mut egui::Ui, state: &mut VisualizationState) {
    // Transition: HidingOverlays → WaitingForScreenshot (request screenshot)
    if state.screenshot_export == ScreenshotStateMachine::HidingOverlays {
        state.screenshot_export = ScreenshotStateMachine::WaitingForScreenshot;
        ui.ctx()
            .send_viewport_cmd(egui::ViewportCommand::Screenshot(egui::UserData::default()));
    }

    // Handle screenshot result
    ui.input(|i| {
        for event in &i.raw.events {
            if let egui::Event::Screenshot { image, .. } = event {
                if state.screenshot_export == ScreenshotStateMachine::WaitingForScreenshot {
                    if let Some(graph_rect) = state.view.graph_rect {
                        let graph_image = image.region(&graph_rect, Some(i.pixels_per_point()));
                        save_screenshot_as_png(&graph_image);
                    } else {
                        log::error!("No graph rect stored for screenshot export");
                    }
                    state.screenshot_export = ScreenshotStateMachine::Idle;
                }
            }
        }
    });
}

/// Save the graph screenshot as a PNG file.
fn save_screenshot_as_png(image: &egui::ColorImage) {
    let width = image.width() as u32;
    let height = image.height() as u32;
    let pixels = image.as_raw();

    // Convert RGBA to ImageBuffer
    let img_buffer = image::RgbaImage::from_raw(width, height, pixels.to_vec())
        .expect("Failed to create image buffer");

    // Generate filename with timestamp
    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let filename = format!("fosr_graph_{}.png", timestamp);

    // Convert to PNG bytes
    let mut buffer = Vec::new();
    match img_buffer.write_to(
        &mut std::io::Cursor::new(&mut buffer),
        image::ImageFormat::Png,
    ) {
        Ok(_) => {
            #[cfg(not(target_arch = "wasm32"))]
            {
                match crate::shared::file_io::save_file_desktop(&buffer, &filename) {
                    Ok(file_handle) => {
                        log::info!("Exported graph to {}", file_handle.path().to_string_lossy());
                    }
                    Err(e) => {
                        log::error!("Failed to save graph PNG: {:?}", e);
                    }
                }
            }

            #[cfg(target_arch = "wasm32")]
            {
                let filename_clone = filename.clone();
                wasm_bindgen_futures::spawn_local(async move {
                    match crate::shared::file_io::save_file_wasm(&buffer, &filename_clone).await {
                        Ok(_) => log::info!("Exported graph to {}", filename_clone),
                        Err(e) => log::error!("Failed to save PNG on WASM: {:?}", e),
                    }
                });
            }
        }
        Err(e) => log::error!("Failed to write PNG to buffer: {}", e),
    }
}
