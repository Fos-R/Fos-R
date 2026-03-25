//! YAML editor with syntax highlighting and error line markers.

use crate::shared::config::parser::parse_config_yaml;
use crate::shared::config::state::ConfigFileState;
use crate::shared::constants::colors::COLOR_ERROR;
use crate::shared::constants::ui::{YAML_EDITOR_ROWS, YAML_GUTTER_PADDING, YAML_ICON_COL_WIDTH};
use eframe::egui;

/// Extract line numbers from YAML parse error messages.
///
/// Parses "line N" patterns from error strings to highlight problematic lines.
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

/// Metrics for rendering the line number gutter.
struct GutterMetrics {
    /// Width of a single digit in the current font.
    digit_width: f32,
    /// Number of digits needed for the largest line number.
    digits: usize,
    /// Total width of the gutter column.
    width: f32,
    /// Height of a single line of text.
    line_height: f32,
    /// Font for gutter text.
    font_id: egui::FontId,
}

impl GutterMetrics {
    /// Calculate gutter metrics from the content and UI style.
    fn from_content(ui: &egui::Ui, line_count: usize) -> Self {
        let font_id = egui::TextStyle::Monospace.resolve(ui.style());
        let line_height = ui.fonts_mut(|f| f.row_height(&font_id));
        let digit_width = ui.fonts_mut(|f| f.glyph_width(&font_id, '0'));
        let digits = line_count.to_string().len();

        Self {
            digit_width,
            digits,
            width: digit_width * digits as f32 + YAML_GUTTER_PADDING + YAML_ICON_COL_WIDTH,
            line_height,
            font_id,
        }
    }
}

/// Editable YAML Editor with syntax highlighting and error markers.
pub fn render_yaml_editor(ui: &mut egui::Ui, state: &mut ConfigFileState) {
    if state.config_file_content.is_none() {
        ui.label("No configuration file selected.");
        return;
    }

    // Display error banner if parsing failed
    let error_lines = render_error_banner(ui, state);

    let mut content = state.config_file_content.clone().unwrap();
    let line_count = content.lines().count().max(1);
    let metrics = GutterMetrics::from_content(ui, line_count);

    let gutter_color = ui.visuals().weak_text_color();
    let gutter_bg = ui.visuals().extreme_bg_color;

    let scroll_offset_id = ui.make_persistent_id("yaml_editor_scroll_y");
    let scroll_y: f32 = ui.data(|d| d.get_temp(scroll_offset_id).unwrap_or(0.0));

    let mut editor_changed = false;
    let mut new_scroll_y = scroll_y;

    // Sync scroll position between gutter and editor
    ui.spacing_mut().item_spacing.x = 0.0;
    ui.horizontal_top(|ui| {
        let available_height = ui.available_height();

        // Allocate and render the gutter
        let (gutter_rect, _) = ui.allocate_exact_size(
            egui::vec2(metrics.width, available_height),
            egui::Sense::hover(),
        );

        ui.painter().rect_filled(gutter_rect, 0.0, gutter_bg);
        render_gutter(
            ui,
            &gutter_rect,
            &metrics,
            scroll_y,
            line_count,
            &error_lines,
            gutter_color,
        );

        // Syntax-highlighted editor
        let theme = egui_extras::syntax_highlighting::CodeTheme::from_memory(ui.ctx(), ui.style());
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
                        .desired_rows(YAML_EDITOR_ROWS)
                        .lock_focus(true)
                        .desired_width(f32::INFINITY)
                        .layouter(&mut layouter),
                )
            });

        new_scroll_y = scroll_out.state.offset.y;
        editor_changed = scroll_out.inner.changed();
    });

    // Persist scroll position
    ui.data_mut(|d| d.insert_temp(scroll_offset_id, new_scroll_y));

    // Re-parse if content changed
    if editor_changed {
        state.config_file_content = Some(content);
        parse_config_yaml(state);
    }
}

/// Render error banner and return parsed error line numbers.
fn render_error_banner(ui: &mut egui::Ui, state: &ConfigFileState) -> Vec<usize> {
    if let Some(err) = &state.config_error {
        ui.colored_label(
            COLOR_ERROR,
            format!(
                "{} YAML parsing failed",
                egui_material_icons::icons::ICON_WARNING
            ),
        );
        ui.colored_label(COLOR_ERROR, err);
        ui.separator();
        parse_error_lines(err)
    } else {
        Vec::new()
    }
}

/// Render the line number gutter with optional error markers.
fn render_gutter(
    ui: &mut egui::Ui,
    gutter_rect: &egui::Rect,
    metrics: &GutterMetrics,
    scroll_y: f32,
    line_count: usize,
    error_lines: &[usize],
    default_color: egui::Color32,
) {
    let first_visible = (scroll_y / metrics.line_height).floor() as usize;
    let visible_count = (gutter_rect.height() / metrics.line_height).ceil() as usize + 2;

    for i in first_visible..(first_visible + visible_count).min(line_count) {
        let line_num = i + 1;
        let y_offset = i as f32 * metrics.line_height - scroll_y;
        let y = gutter_rect.top() + y_offset;

        if y > gutter_rect.bottom() {
            break;
        }

        let is_error = error_lines.contains(&line_num);
        let num_color = if is_error { COLOR_ERROR } else { default_color };

        // Right-aligned line number
        let num_str = format!("{:>width$}", line_num, width = metrics.digits);
        ui.painter().text(
            egui::pos2(gutter_rect.left() + 2.0, y),
            egui::Align2::LEFT_TOP,
            num_str,
            metrics.font_id.clone(),
            num_color,
        );

        // Error icon for lines with parse errors
        if is_error {
            let num_col_right = gutter_rect.left() + metrics.digit_width * metrics.digits as f32 + 4.0;
            let icon_rect = egui::Rect::from_min_size(
                egui::pos2(num_col_right, y),
                egui::vec2(YAML_ICON_COL_WIDTH, metrics.line_height),
            );
            ui.scope_builder(egui::UiBuilder::new().max_rect(icon_rect), |ui| {
                ui.colored_label(COLOR_ERROR, egui_material_icons::icons::ICON_WARNING);
            });
        }
    }
}
