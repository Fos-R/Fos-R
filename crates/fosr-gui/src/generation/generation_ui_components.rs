// The `timezone_picker` function is inspired by egui's ComboBox (combo_box.rs).
//
// egui is licensed under MIT OR Apache-2.0.
//
// MIT License
//
// Copyright (c) 2018-2021 Emil Ernerfeldt <emil.ernerfeldt@gmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use super::generation_tab::{GenerationTabState, UiStatus};
use super::generation_validation::FieldValidation;
use chrono_tz::TZ_VARIANTS;
use eframe::egui::{self, epaint};

/// Display the error in red
pub fn show_field_error(ui: &mut egui::Ui, validation: &FieldValidation) {
    if let Some(msg) = &validation.error {
        ui.add_space(6.0);
        ui.colored_label(egui::Color32::RED, msg);
    }
}

pub fn show_status(ui: &mut egui::Ui, status: &UiStatus) {
    match status {
        UiStatus::Idle => {}
        UiStatus::Generating => {
            ui.label("Generating file…");
        }
        UiStatus::Generated => {
            ui.label("File generated. You can save it.");
        }
        #[cfg(not(target_arch = "wasm32"))]
        UiStatus::Saved(msg) => {
            ui.label(format!("File saved. {}", msg));
        }
        #[cfg(not(target_arch = "wasm32"))]
        UiStatus::Error(msg) => {
            ui.colored_label(egui::Color32::RED, format!("Error: {msg}"));
        }
    }
}

pub fn timezone_picker(ui: &mut egui::Ui, state: &mut GenerationTabState) {
    let popup_id = ui.make_persistent_id("tz_popup");
    let is_open = egui::Popup::is_id_open(ui.ctx(), popup_id);

    // --- ComboBox-style button (inspired by egui's combo_box.rs button_frame) ---
    let width = 160.0_f32;
    let margin = ui.spacing().button_padding;
    let icon_spacing = ui.spacing().icon_spacing;
    let icon_size = egui::Vec2::splat(ui.spacing().icon_width);
    let desired_size = egui::vec2(width, ui.spacing().interact_size.y);

    let (rect, response) = ui.allocate_exact_size(desired_size, egui::Sense::click());

    if ui.is_rect_visible(rect) {
        let visuals = if is_open {
            &ui.visuals().widgets.open
        } else {
            ui.style().interact(&response)
        };

        // Button background
        ui.painter().add(epaint::RectShape::new(
            rect.expand(visuals.expansion),
            visuals.corner_radius,
            visuals.weak_bg_fill,
            visuals.bg_stroke,
            epaint::StrokeKind::Inside,
        ));

        let inner = rect.shrink2(margin);

        // Triangle icon on the right
        let icon_rect = egui::Align2::RIGHT_CENTER.align_size_within_rect(icon_size, inner);
        let tri = egui::Rect::from_center_size(
            icon_rect.center(),
            egui::vec2(icon_rect.width() * 0.7, icon_rect.height() * 0.45),
        );
        ui.painter().add(egui::Shape::convex_polygon(
            vec![tri.left_top(), tri.right_top(), tri.center_bottom()],
            visuals.fg_stroke.color,
            egui::Stroke::NONE,
        ));

        // Selected text on the left
        let text_rect = inner.with_max_x(icon_rect.left() - icon_spacing);
        let galley = ui.painter().layout_no_wrap(
            state.timezone_input.clone(),
            egui::TextStyle::Button.resolve(ui.style()),
            visuals.text_color(),
        );
        let text_pos = egui::Align2::LEFT_CENTER
            .align_size_within_rect(galley.size(), text_rect)
            .min;
        ui.painter()
            .with_clip_rect(text_rect)
            .galley(text_pos, galley, visuals.text_color());
    }

    let response = response.on_hover_text(&state.timezone_input);

    // --- Popup (inspired by combo_box_dyn) ---
    egui::Popup::menu(&response)
        .id(popup_id)
        .close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside)
        .width(response.rect.width())
        .show(|ui| {
            ui.set_min_width(response.rect.width());
            // Override cached Area height constraint
            // (workaround for https://github.com/emilk/egui/issues/5225)
            ui.set_max_height(450.0);

            // Search input with auto-focus on open
            let edit_id = ui.make_persistent_id("tz_search");
            ui.add(
                egui::TextEdit::singleline(&mut state.timezone_input)
                    .hint_text("Search...")
                    .id(edit_id),
            );
            if ui.memory(|m| m.focused().is_none()) {
                ui.memory_mut(|m| m.request_focus(edit_id));
            }

            ui.separator();

            // Filtered timezone list
            egui::ScrollArea::vertical()
                .max_height(400.0)
                .show(ui, |ui| {
                    ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Extend);
                    let filter = state.timezone_input.to_lowercase();
                    for tz in TZ_VARIANTS {
                        let tz_str = tz.to_string();
                        if filter.is_empty() || tz_str.to_lowercase().contains(&filter) {
                            if ui
                                .selectable_label(state.timezone_input == tz_str, &tz_str)
                                .clicked()
                            {
                                state.timezone_input = tz_str;
                                ui.close();
                            }
                        }
                    }
                });
        });
}
