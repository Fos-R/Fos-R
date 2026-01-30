use chrono::NaiveTime;
use eframe::egui;
use egui::{Area, Button, Frame, InnerResponse, Key, Order, RichText, Widget};

use super::popup::TimePickerPopup;

#[derive(Default, Clone, serde::Deserialize, serde::Serialize)]
pub(crate) struct TimePickerButtonState {
    pub picker_visible: bool,
}

pub struct TimePickerButton<'a> {
    selection: &'a mut NaiveTime,
    id_salt: Option<&'a str>,
    show_icon: bool,
    format: String,
    show_clockface: bool,
    use_12_hour_clock: bool,
    show_seconds: bool,
    use_dragvalue: bool,
}

impl<'a> TimePickerButton<'a> {
    pub fn new(selection: &'a mut NaiveTime) -> Self {
        Self {
            selection,
            id_salt: None,
            show_icon: true,
            format: "%H:%M".to_string(),
            show_clockface: true,
            use_12_hour_clock: false,
            show_seconds: false,
            use_dragvalue: false,
        }
    }

    pub fn show_seconds(mut self, show_seconds: bool) -> Self {
        self.show_seconds = show_seconds;
        self
    }

    pub fn use_dragvalue(mut self, use_dragvalue: bool) -> Self {
        self.use_dragvalue = use_dragvalue;
        self
    }
}

impl Widget for TimePickerButton<'_> {
    fn ui(self, ui: &mut egui::Ui) -> egui::Response {
        let id = ui.make_persistent_id(self.id_salt);
        let mut button_state = ui
            .data_mut(|data| data.get_persisted::<TimePickerButtonState>(id))
            .unwrap_or_default();

        let mut text = if self.show_icon {
            RichText::new(format!("{} 🕒", self.selection.format(&self.format)))
        } else {
            RichText::new(self.selection.format(&self.format).to_string())
        };

        let visuals = ui.visuals().widgets.open;
        if button_state.picker_visible {
            text = text.color(visuals.text_color());
        }

        let mut button = Button::new(text);
        if button_state.picker_visible {
            button = button.fill(visuals.weak_bg_fill).stroke(visuals.bg_stroke);
        }

        let mut button_response = ui.add(button);
        if button_response.clicked() {
            button_state.picker_visible = true;
            ui.data_mut(|data| data.insert_persisted(id, button_state.clone()));
        }

        if button_state.picker_visible {
            let width = 250.;
            let mut pos = button_response.rect.left_bottom();
            let width_with_padding = width
                + ui.style().spacing.item_spacing.x
                + ui.style().spacing.window_margin.leftf()
                + ui.style().spacing.window_margin.rightf();

            if pos.x + width_with_padding > ui.clip_rect().right() {
                pos.x = button_response.rect.right() - width_with_padding;
            }

            pos.x = pos.x.max(ui.style().spacing.window_margin.leftf());

            let InnerResponse {
                inner: saved,
                response: area_response,
            } = Area::new(ui.make_persistent_id(self.id_salt))
                .kind(egui::UiKind::Picker)
                .order(Order::Foreground)
                .fixed_pos(pos)
                .show(ui.ctx(), |ui| {
                    let frame = Frame::popup(ui.style());
                    frame
                        .show(ui, |ui| {
                            ui.set_min_width(width);
                            ui.set_max_width(width);

                            TimePickerPopup {
                                selection: self.selection,
                                button_id: id,
                                show_clockface: self.show_clockface,
                                show_seconds: self.show_seconds,
                                use_12_hour_clock: self.use_12_hour_clock,
                                use_dragvalue: self.use_dragvalue,
                            }
                            .draw(ui)
                        })
                        .inner
                });

            if saved {
                button_response.mark_changed();
            }

            let any_popup_open = ui.ctx().is_popup_open();
            if !button_response.clicked()
                && !any_popup_open
                && (ui.input(|i| i.key_pressed(Key::Escape)) || area_response.clicked_elsewhere())
            {
                button_state.picker_visible = false;
                ui.data_mut(|data| data.insert_persisted(id, button_state));
            }
        }

        button_response
    }
}
