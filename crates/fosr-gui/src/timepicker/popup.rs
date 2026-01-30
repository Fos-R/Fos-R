use std::fmt::Display;

use chrono::{NaiveTime, Timelike};
use eframe::egui;
use egui::{
    Align2, Color32, DragValue, FontId, Id, Layout, Painter, Pos2, Response, RichText, Sense, Ui,
    Vec2,
};

use super::button::TimePickerButtonState;

#[derive(Default, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
enum TimeFrame {
    #[default]
    Hour,
    Minute,
    Second,
}

#[derive(Default, Clone, serde::Deserialize, serde::Serialize)]
enum AmPm {
    #[default]
    Am,
    Pm,
}

impl Display for AmPm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AmPm::Am => write!(f, "AM"),
            AmPm::Pm => write!(f, "PM"),
        }
    }
}

#[derive(Default, Clone, serde::Deserialize, serde::Serialize)]
pub(crate) struct TimePickerPopupState {
    hour: u32,
    minute: u32,
    second: u32,
    setup: bool,
    timeframe: TimeFrame,
    am_pm: AmPm,
}

pub(crate) struct TimePickerPopup<'a> {
    pub selection: &'a mut NaiveTime,
    pub button_id: Id,
    pub show_clockface: bool,
    pub use_12_hour_clock: bool,
    pub show_seconds: bool,
    pub use_dragvalue: bool,
}

impl TimePickerPopup<'_> {
    pub fn draw(&mut self, ui: &mut Ui) -> bool {
        let id = ui.make_persistent_id("time_picker");
        let mut popup_state = ui
            .data_mut(|data| data.get_persisted::<TimePickerPopupState>(id))
            .unwrap_or_default();
        if !popup_state.setup {
            popup_state.hour = self.selection.hour();
            popup_state.minute = self.selection.minute();
            popup_state.second = self.selection.second();
            popup_state.setup = true;
            ui.data_mut(|data| data.insert_persisted(id, popup_state.clone()));
        }

        let (mut close, mut saved) = (false, false);

        ui.horizontal(|ui| {
            let mut hour_rect = None;
            let mut minute_rect = None;
            let mut second_rect = None;

            if self.use_dragvalue {
                let range = if self.use_12_hour_clock {
                    0..=11
                } else {
                    0..=23
                };

                let r = ui.add(DragValue::new(&mut popup_state.hour).range(range));
                hour_rect = Some(r.rect);
                if r.clicked() || r.changed() {
                    popup_state.timeframe = TimeFrame::Hour;
                }
            } else if ui
                .button(RichText::new(popup_state.hour.to_string()).size(18.))
                .clicked()
            {
                popup_state.timeframe = TimeFrame::Hour;
            }

            ui.label(RichText::new("h :").monospace());

            if self.use_dragvalue {
                let r = ui.add(DragValue::new(&mut popup_state.minute).range(0..=59));
                minute_rect = Some(r.rect);
                if r.clicked() || r.changed() {
                    popup_state.timeframe = TimeFrame::Minute;
                }
            } else if ui
                .button(RichText::new(popup_state.minute.to_string()).size(18.))
                .clicked()
            {
                popup_state.timeframe = TimeFrame::Minute;
            }

            if self.show_seconds {
                ui.label(RichText::new("m :").monospace());

                if self.use_dragvalue {
                    let r = ui.add(DragValue::new(&mut popup_state.second).range(0..=59));
                    second_rect = Some(r.rect);
                    if r.clicked() || r.changed() {
                        popup_state.timeframe = TimeFrame::Second;
                    }
                } else if ui
                    .button(RichText::new(popup_state.second.to_string()).size(18.))
                    .clicked()
                {
                    popup_state.timeframe = TimeFrame::Second;
                }

                ui.label(RichText::new("s").monospace());
            } else {
                ui.label(RichText::new("m").monospace());
            }

            if self.use_12_hour_clock {
                if ui
                    .button(RichText::new(popup_state.am_pm.to_string()).size(18.))
                    .clicked()
                {
                    popup_state.am_pm = match popup_state.am_pm {
                        AmPm::Am => AmPm::Pm,
                        AmPm::Pm => AmPm::Am,
                    };
                }
            }

            // Highlight the active drag value with a border
            let active_rect = match popup_state.timeframe {
                TimeFrame::Hour => hour_rect,
                TimeFrame::Minute => minute_rect,
                TimeFrame::Second => second_rect,
            };
            if let Some(rect) = active_rect {
                let stroke = egui::Stroke::new(1.5, ui.visuals().selection.stroke.color);
                ui.painter().rect_stroke(rect.expand(1.0), 2.0, stroke, egui::StrokeKind::Outside);
            }
        });

        let text_color = ui.visuals().text_color();
        let highlight_color = ui.visuals().selection.bg_fill.linear_multiply(0.5);

        let (rect, response) =
            ui.allocate_exact_size(Vec2::new(250., 250.), Sense::click_and_drag());
        let painter = ui.painter_at(rect);

        let center = rect.center();
        let radius = rect.width() / 2.0;
        let r_outer = radius * 0.8;
        let r_inner = radius * 0.55;

        let time = match popup_state.timeframe {
            TimeFrame::Hour => &mut popup_state.hour,
            TimeFrame::Minute => &mut popup_state.minute,
            TimeFrame::Second => &mut popup_state.second,
        };

        if self.show_clockface {
            draw_timepicker(
                r_outer,
                r_inner,
                center,
                &painter,
                &response,
                &popup_state.timeframe,
                time,
                self.use_12_hour_clock,
                text_color,
                highlight_color,
            );

            // Auto-advance to next timeframe when the user releases the pointer on the clock
            if response.drag_stopped() || response.clicked() {
                popup_state.timeframe = match popup_state.timeframe {
                    TimeFrame::Hour => TimeFrame::Minute,
                    TimeFrame::Minute if self.show_seconds => TimeFrame::Second,
                    _ => popup_state.timeframe.clone(),
                };
            }
        }

        ui.horizontal(|ui| {
            ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Save").clicked() {
                    let mut hour = popup_state.hour;
                    if self.use_12_hour_clock {
                        match popup_state.am_pm {
                            AmPm::Am => {}
                            AmPm::Pm => hour += 12,
                        }
                    }

                    *self.selection =
                        NaiveTime::from_hms_opt(hour, popup_state.minute, popup_state.second)
                            .expect("Could not create NaiveTime");
                    saved = true;
                    close = true;
                }

                if ui.button("Cancel").clicked() {
                    close = true;
                }
            });
        });

        ui.data_mut(|data| {
            data.insert_persisted(id, popup_state.clone());
        });

        if close {
            popup_state.setup = false;
            ui.data_mut(|data| {
                data.insert_persisted(id, popup_state);
                data.get_persisted_mut_or_default::<TimePickerButtonState>(self.button_id)
                    .picker_visible = false;
            });
        }

        saved && close
    }
}

fn draw_timepicker(
    radius_outer: f32,
    radius_inner: f32,
    center: Pos2,
    painter: &Painter,
    response: &Response,
    timeframe: &TimeFrame,
    time: &mut u32,
    use_12_hour_format: bool,
    text_color: Color32,
    highlight_color: Color32,
) {
    for i in 0..12 {
        let angle = (-90. + 30. * i as f32).to_radians();
        let x_outer = center.x + radius_outer * angle.cos();
        let y_outer = center.y + radius_outer * angle.sin();

        let x_inner = center.x + radius_inner * angle.cos();
        let y_inner = center.y + radius_inner * angle.sin();

        match *timeframe {
            TimeFrame::Hour => {
                painter.text(
                    Pos2::new(x_outer, y_outer),
                    Align2::CENTER_CENTER,
                    i.to_string(),
                    FontId::monospace(12.0),
                    text_color,
                );

                if !use_12_hour_format {
                    painter.text(
                        Pos2::new(x_inner, y_inner),
                        Align2::CENTER_CENTER,
                        (i + 12).to_string(),
                        FontId::monospace(12.0),
                        text_color,
                    );
                }

                if *time == i {
                    painter.circle_filled(
                        Pos2::new(x_outer, y_outer),
                        15.,
                        highlight_color,
                    );
                }

                if *time == (i + 12) {
                    painter.circle_filled(
                        Pos2::new(x_inner, y_inner),
                        15.,
                        highlight_color,
                    );
                }
            }
            TimeFrame::Minute | TimeFrame::Second => {
                painter.text(
                    Pos2::new(x_outer, y_outer),
                    Align2::CENTER_CENTER,
                    (i * 5).to_string(),
                    FontId::monospace(12.0),
                    text_color,
                );

                if *time % 5 == 0 && *time == i * 5 {
                    painter.circle_filled(
                        Pos2::new(x_outer, y_outer),
                        15.,
                        highlight_color,
                    );
                }
            }
        }
    }

    if let Some(pos) = response.interact_pointer_pos() {
        let angle = (pos - center).angle();
        let distance = (pos - center).length();

        match *timeframe {
            TimeFrame::Hour => {
                let mut h = (angle.to_degrees() + 90. + 15.).rem_euclid(360.) as u32 / 30. as u32;
                if distance < radius_outer - 15. && !use_12_hour_format {
                    h += 12;
                }
                *time = h;
            }
            TimeFrame::Minute | TimeFrame::Second => {
                let mut t = (angle.to_degrees() + 90. + 3.).rem_euclid(360.) as u32 / 6. as u32;
                if t == 60 {
                    t = 0;
                }
                *time = t;
            }
        }
    }

    match *timeframe {
        TimeFrame::Hour => {
            let angle = (*time as f32 * 30. - 90.).to_radians();
            if *time < 12 {
                let end = center + Vec2::angled(angle) * (radius_outer - 15.);
                painter.line_segment([center, end], (2., text_color));
            } else {
                let end = center + Vec2::angled(angle) * (radius_inner - 15.);
                painter.line_segment([center, end], (2., text_color));
            }
        }
        TimeFrame::Minute | TimeFrame::Second => {
            let angle = (*time as f32 * 6. - 90.).to_radians();

            let radius = if *time % 5 == 0 {
                radius_outer - 15.
            } else {
                radius_outer
            };

            let end = center + Vec2::angled(angle) * radius;
            painter.line_segment([center, end], (2., text_color));

            if *time % 5 != 0 {
                painter.circle_filled(end, 4., text_color);
            }
        }
    }

    painter.circle_filled(center, 4., text_color);
}
