//! Reusable searchable ComboBox widget.
//!
//! Provides a custom-painted ComboBox button with a popup containing
//! a search field and scrollable item list. Inspired by egui's ComboBox
//! (MIT OR Apache-2.0, Copyright (c) 2018-2021 Emil Ernerfeldt).

use crate::shared::constants::ui::{
    DEFAULT_COMBO_LIST_MAX_HEIGHT, DEFAULT_COMBO_POPUP_MAX_HEIGHT, DEFAULT_COMBO_WIDTH,
};
use eframe::egui::{self, epaint};

/// Custom ComboBox with built-in search functionality.
///
/// Renders a ComboBox-style button that opens a popup with a search field.
/// The caller provides the content of the scrollable item list via `show()`.
pub struct SearchableCombo {
    id: egui::Id,
    selected_text: String,
    width: f32,
    popup_max_height: f32,
    list_max_height: f32,
}

impl SearchableCombo {
    /// Create a new searchable combo.
    ///
    /// `selected_text` is displayed on the button when the popup is closed.
    pub fn new(id: impl Into<egui::Id>, selected_text: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            selected_text: selected_text.into(),
            width: DEFAULT_COMBO_WIDTH,
            popup_max_height: DEFAULT_COMBO_POPUP_MAX_HEIGHT,
            list_max_height: DEFAULT_COMBO_LIST_MAX_HEIGHT,
        }
    }

    /// Set the button width.
    pub fn width(mut self, width: f32) -> Self {
        self.width = width;
        self
    }

    /// Set the popup maximum height (includes search field + separator).
    pub fn popup_max_height(mut self, height: f32) -> Self {
        self.popup_max_height = height;
        self
    }

    /// Set the scrollable list maximum height.
    pub fn list_max_height(mut self, height: f32) -> Self {
        self.list_max_height = height;
        self
    }

    /// Show the combo button and popup.
    ///
    /// `add_contents` receives `(ui, filter_string)` and should render the
    /// filtered item list inside a scroll area. Returns `None` if the popup
    /// is not open, otherwise returns the result of `add_contents`.
    pub fn show<R>(
        self,
        ui: &mut egui::Ui,
        add_contents: impl FnOnce(&mut egui::Ui, &str) -> R,
    ) -> egui::InnerResponse<Option<R>> {
        let is_open = egui::Popup::is_id_open(ui.ctx(), self.id);

        // --- ComboBox-style button ---
        let response = paint_combo_button(ui, &self.selected_text, self.width, is_open);

        // --- Popup with search + scrollable content ---
        let inner_response = egui::Popup::menu(&response)
            .id(self.id)
            .close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside)
            .width(response.rect.width())
            .show(|ui| {
                // Make the popup content at least as large as the button
                ui.set_min_width(response.rect.width());

                ui.set_max_height(self.popup_max_height);

                let search_id = self.id.with("search");
                let filter = render_search_field(ui, search_id);

                ui.separator();

                egui::ScrollArea::vertical()
                    .max_height(self.list_max_height)
                    .auto_shrink([true, true])
                    .show(ui, |ui| add_contents(ui, &filter))
                    .inner
            });

        // Update response's inner to match the scroll area result
        egui::InnerResponse {
            inner: inner_response.map(|ir| ir.inner),
            response,
        }
    }
}

/// Render the search TextEdit with auto-focus. Returns the current filter string.
fn render_search_field(ui: &mut egui::Ui, search_id: egui::Id) -> String {
    // `data_mut` allows to store temporary data for this widget.
    // Here we retrieve the search value from last frame
    let mut search_text: String =
        ui.data_mut(|d| d.get_temp::<String>(search_id).unwrap_or_default());

    let edit_id = search_id.with("edit");
    let search_resp = ui.add(
        egui::TextEdit::singleline(&mut search_text)
            .hint_text("Search...")
            .id(edit_id),
    );

    // Autofocus on the search field when the popup is opened
    if ui.memory(|m| m.focused().is_none()) {
        ui.memory_mut(|m| m.request_focus(search_resp.id));
    }

    // Store search value for next frame
    ui.data_mut(|d| d.insert_temp(search_id, search_text.clone()));

    search_text.to_lowercase()
}

/// Paint a ComboBox-style button with dropdown arrow.
///
/// Returns the button response for popup triggering and hover text.
fn paint_combo_button(ui: &mut egui::Ui, text: &str, width: f32, is_open: bool) -> egui::Response {
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
            text.to_string(),
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

    response
}
