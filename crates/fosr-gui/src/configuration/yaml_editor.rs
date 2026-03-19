use crate::shared::configuration_file::{ConfigurationFileState, parse_config_yaml};
use eframe::egui;

fn parse_error_lines(err: &str) -> Vec<usize> {
    let mut found = Vec::new();
    let mut search = err;
    while let Some(pos) = search.find("line ") {
        let rest = &search[pos + 5..];
        let num: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if let Ok(n) = num.parse::<usize>() {
            if !found.contains(&n) {
                found.push(n);
            }
        }
        search = &search[pos + 5..];
    }
    found
}

/// Editable YAML Editor
pub fn ui_yaml_editor(ui: &mut egui::Ui, state: &mut ConfigurationFileState) {
    if state.config_file_content.is_none() {
        ui.label("No configuration file selected.");
        return;
    }

    let error_lines: Vec<usize> = if let Some(err) = &state.parse_error {
        ui.colored_label(
            egui::Color32::RED,
            format!(
                "{} YAML parsing failed",
                egui_material_icons::icons::ICON_WARNING
            ),
        );
        ui.colored_label(egui::Color32::RED, err);
        ui.separator();
        parse_error_lines(err)
    } else {
        Vec::new()
    };

    let mut content = state.config_file_content.clone().unwrap();
    let line_count = content.lines().count().max(1);

    let theme = egui_extras::syntax_highlighting::CodeTheme::from_memory(ui.ctx(), ui.style());
    let font_id = egui::TextStyle::Monospace.resolve(ui.style());
    let line_height = ui.fonts_mut(|f| f.row_height(&font_id));
    let digit_width = ui.fonts_mut(|f| f.glyph_width(&font_id, '0'));
    let digits = line_count.to_string().len();
    let icon_col_width = 20.0;
    let gutter_width = digit_width * digits as f32 + 6.0 + icon_col_width;

    let gutter_color = ui.visuals().weak_text_color();
    let error_color = egui::Color32::from_rgb(220, 50, 50);
    let gutter_bg = ui.visuals().extreme_bg_color;

    let scroll_offset_id = ui.make_persistent_id("yaml_editor_scroll_y");
    let scroll_y: f32 = ui.data(|d| d.get_temp(scroll_offset_id).unwrap_or(0.0));

    let mut editor_changed = false;
    let mut new_scroll_y = scroll_y;

    ui.spacing_mut().item_spacing.x = 0.0;
    ui.horizontal_top(|ui| {
        let available_height = ui.available_height();

        let (gutter_rect, _) = ui.allocate_exact_size(
            egui::vec2(gutter_width, available_height),
            egui::Sense::hover(),
        );

        ui.painter().rect_filled(gutter_rect, 0.0, gutter_bg);

        let first_visible = (scroll_y / line_height).floor() as usize;
        let visible_count = (available_height / line_height).ceil() as usize + 2;

        for i in first_visible..(first_visible + visible_count).min(line_count) {
            let line_num = i + 1;
            let y_offset = i as f32 * line_height - scroll_y;
            let y = gutter_rect.top() + y_offset;

            if y > gutter_rect.bottom() {
                break;
            }

            let is_error = error_lines.contains(&line_num);
            let num_color = if is_error { error_color } else { gutter_color };

            let num_str = format!("{:>width$}", line_num, width = digits);
            let num_col_right = gutter_rect.left() + digit_width * digits as f32 + 4.0;
            ui.painter().text(
                egui::pos2(gutter_rect.left() + 2.0, y),
                egui::Align2::LEFT_TOP,
                num_str,
                font_id.clone(),
                num_color,
            );

            if is_error {
                let icon_rect = egui::Rect::from_min_size(
                    egui::pos2(num_col_right, y),
                    egui::vec2(icon_col_width, line_height),
                );
                ui.scope_builder(egui::UiBuilder::new().max_rect(icon_rect), |ui| {
                    ui.colored_label(error_color, egui_material_icons::icons::ICON_WARNING);
                });
            }
        }

        let mut layouter = |ui: &egui::Ui, text: &dyn egui::TextBuffer, wrap_width: f32| {
            let mut layout_job = egui_extras::syntax_highlighting::highlight(
                ui.ctx(),
                ui.style(),
                &theme,
                text.as_str(),
                "yaml",
            );
            layout_job.wrap.max_width = wrap_width;
            ui.fonts_mut(|f| f.layout_job(layout_job))
        };

        let scroll_out = egui::ScrollArea::vertical()
            .id_salt("yaml_scroll_area")
            .show(ui, |ui| {
                ui.add(
                    egui::TextEdit::multiline(&mut content)
                        .font(egui::TextStyle::Monospace)
                        .code_editor()
                        .desired_rows(20)
                        .lock_focus(true)
                        .desired_width(f32::INFINITY)
                        .layouter(&mut layouter),
                )
            });

        new_scroll_y = scroll_out.state.offset.y;
        editor_changed = scroll_out.inner.changed();
    });

    ui.data_mut(|d| d.insert_temp(scroll_offset_id, new_scroll_y));

    if editor_changed {
        state.config_file_content = Some(content);
        parse_config_yaml(state);
    }
}
