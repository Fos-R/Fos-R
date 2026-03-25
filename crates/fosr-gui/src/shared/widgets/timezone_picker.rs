//! Timezone picker widget with search functionality.

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

use crate::shared::constants::ui::{
    TIMEZONE_LIST_MAX_HEIGHT, TIMEZONE_PICKER_WIDTH, TIMEZONE_POPUP_MAX_HEIGHT,
};
use chrono_tz::TZ_VARIANTS;
use eframe::egui::{self, epaint};

/// Timezone picker with search functionality.
pub fn timezone_picker(ui: &mut egui::Ui, timezone_input: &mut String) {
    let popup_id = ui.make_persistent_id("tz_popup");
    let is_open = egui::Popup::is_id_open(ui.ctx(), popup_id);

    // --- ComboBox-style button (inspired by egui's combo_box.rs button_frame) ---
    let margin = ui.spacing().button_padding;
    let icon_spacing = ui.spacing().icon_spacing;
    let icon_size = egui::Vec2::splat(ui.spacing().icon_width);
    let desired_size = egui::vec2(TIMEZONE_PICKER_WIDTH, ui.spacing().interact_size.y);

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
            timezone_input.clone(),
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

    let response = response.on_hover_text(&*timezone_input);

    // --- Popup (inspired by combo_box_dyn) ---
    egui::Popup::menu(&response)
        .id(popup_id)
        .close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside)
        .width(response.rect.width())
        .show(|ui| {
            ui.set_min_width(response.rect.width());
            // Override cached Area height constraint
            // (workaround for https://github.com/emilk/egui/issues/5225)
            ui.set_max_height(TIMEZONE_POPUP_MAX_HEIGHT);

            // Search input with autofocus on open
            let edit_id = ui.make_persistent_id("tz_search");
            ui.add(
                egui::TextEdit::singleline(timezone_input)
                    .hint_text("Search...")
                    .id(edit_id),
            );
            if ui.memory(|m| m.focused().is_none()) {
                ui.memory_mut(|m| m.request_focus(edit_id));
            }

            ui.separator();

            // Filtered timezone list
            egui::ScrollArea::vertical()
                .max_height(TIMEZONE_LIST_MAX_HEIGHT)
                .show(ui, |ui| {
                    ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Extend);
                    let filter = timezone_input.to_lowercase();
                    for tz in TZ_VARIANTS {
                        let tz_str = tz.to_string();
                        if filter.is_empty() || tz_str.to_lowercase().contains(&filter) {
                            // Display the timezone as a clickable option that updates the input
                            if ui
                                .selectable_label(*timezone_input == tz_str, &tz_str)
                                .clicked()
                            {
                                *timezone_input = tz_str;
                                // Close the first closable parent, which is the popup
                                ui.close();
                            }
                        }
                    }
                });
        });
}
