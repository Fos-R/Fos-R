//! Custom node and edge shapes with protocol colors, icons, and dynamic sizing.
//!
//! egui_graphs rendering:
//! - `DisplayNode` trait: defines how a node is drawn (shapes, labels, icons)
//! - `DisplayEdge` trait: defines how an edge is drawn (lines, arrows, colors)
//! - `closest_boundary_point`: where edges connect to the node boundary
//! - `is_inside`: hit-testing for clicking and dragging

use super::state::{
    EdgeState, LinkDirection, NetworkEdge, NetworkNode, NodeType, SubnetDisplayMode, ZoneDisplay,
};
use crate::shared::assets::{IMG_COMPUTER, IMG_INTERNET, IMG_ROUTER, IMG_SERVER};
use crate::shared::constants::colors::{
    COLOR_EDGE_INACTIVE, COLOR_ICON_TINT_DARK, COLOR_ICON_TINT_LIGHT, COLOR_TEXT_MUTED,
    ZONE_ACCENT_ALPHA_DARK, ZONE_ACCENT_ALPHA_LIGHT, ZONE_ACCENT_BRIGHTEN, ZONE_UNIFORM_RGB,
    color_for_protocol,
};
use crate::shared::constants::ui::{
    EDGE_ARROW_ANGLE_RAD, EDGE_ARROW_SIZE, EDGE_FLOW_SCALE, EDGE_WIDTH_MAX, EDGE_WIDTH_MIN,
    GOLDEN_RATIO_CONJUGATE, NODE_FLOW_SCALE_FACTOR, NODE_RADIUS_MAX, NODE_RADIUS_MIN, SPACING_XS,
    TEXT_SIZE_DEFAULT, TEXT_SIZE_SM, ZONE_BORDER_STROKE_WIDTH, ZONE_COLOR_ALPHA,
    ZONE_COLOR_LIGHTNESS_DARK, ZONE_COLOR_LIGHTNESS_LIGHT, ZONE_COLOR_SATURATION_DARK,
    ZONE_COLOR_SATURATION_LIGHT, ZONE_RECT_ROUNDING,
};
use eframe::egui::{
    self, Color32, Pos2, Rect, Shape, StrokeKind, TextureOptions, Vec2, load::SizeHint,
};
use eframe::epaint::FontsView;
use egui_graphs::{DisplayEdge, DisplayNode, DrawContext, Node, NodeProps};

/// Hybrid linear/proportional scaling.
///
/// Two-phase approach:
/// 1. **Linear phase**: While the max linear value stays below `max_val`,
///    each item grows proportionally to its count.
/// 2. **Proportional phase**: Once linear would exceed `max_val`, switch to
///    ratio-based scaling so the most active item is always at max.
///
/// This ensures smooth growth at low traffic and comparability at high traffic.
fn hybrid_scale(count: u32, max_count: u32, min_val: f32, scale: f32, max_val: f32) -> f32 {
    let max_linear = min_val + max_count as f32 * scale;

    if max_linear < max_val {
        // Linear phase: all edges grow normally
        min_val + count as f32 * scale
    } else {
        // Proportional phase: scale by ratio to max
        let ratio = if max_count > 0 {
            count as f32 / max_count as f32
        } else {
            0.0
        };
        min_val + ratio * (max_val - min_val)
    }
}

fn calculate_node_radius(flow_count: u32, max_flow_count: u32) -> f32 {
    hybrid_scale(
        flow_count,
        max_flow_count,
        NODE_RADIUS_MIN,
        NODE_FLOW_SCALE_FACTOR,
        NODE_RADIUS_MAX,
    )
}

fn calculate_edge_width(flow_count: u32, max_flow_count: u32) -> f32 {
    hybrid_scale(
        flow_count,
        max_flow_count,
        EDGE_WIDTH_MIN,
        EDGE_FLOW_SCALE,
        EDGE_WIDTH_MAX,
    )
}

/// Generate a subnet zone color based on the display mode.
///
/// - `SubnetDisplayMode::Subnet`: uniform color for all subnets.
/// - `SubnetDisplayMode::ColoredSubnets`: golden-ratio hue for distinct colors.
fn subnet_zone_color(idx: usize, dark_mode: bool, mode: SubnetDisplayMode) -> Color32 {
    match mode {
        SubnetDisplayMode::Flat => Color32::TRANSPARENT,
        SubnetDisplayMode::Subnet => {
            let (r, g, b) = ZONE_UNIFORM_RGB;
            Color32::from_rgba_unmultiplied(r, g, b, ZONE_COLOR_ALPHA)
        }
        SubnetDisplayMode::ColoredSubnets => {
            let hue = ((idx as f32 * GOLDEN_RATIO_CONJUGATE) % 1.0) * 360.0;
            if dark_mode {
                hsl_to_color32(
                    hue,
                    ZONE_COLOR_SATURATION_DARK,
                    ZONE_COLOR_LIGHTNESS_DARK,
                    ZONE_COLOR_ALPHA,
                )
            } else {
                hsl_to_color32(
                    hue,
                    ZONE_COLOR_SATURATION_LIGHT,
                    ZONE_COLOR_LIGHTNESS_LIGHT,
                    ZONE_COLOR_ALPHA,
                )
            }
        }
    }
}

/// Convert HSL (hue in degrees, saturation 0-1, lightness 0-1, alpha 0-255) to Color32.
fn hsl_to_color32(h: f32, s: f32, l: f32, a: u8) -> Color32 {
    let c = (1.0 - (2.0 * l - 1.0).abs()) * s;
    let x = c * (1.0 - ((h / 60.0) % 2.0 - 1.0).abs());
    let m = l - c / 2.0;
    let (r1, g1, b1) = match h % 360.0 {
        h if h < 60.0 => (c, x, 0.0),
        h if h < 120.0 => (x, c, 0.0),
        h if h < 180.0 => (0.0, c, x),
        h if h < 240.0 => (0.0, x, c),
        h if h < 300.0 => (x, 0.0, c),
        _ => (c, 0.0, x),
    };
    let r = ((r1 + m) * 255.0) as u8;
    let g = ((g1 + m) * 255.0) as u8;
    let b = ((b1 + m) * 255.0) as u8;
    Color32::from_rgba_unmultiplied(r, g, b, a)
}

/// Brighten a base color in dark mode or keep it with adjusted alpha in light mode.
///
/// Used for zone border and label colors that must stand out against the
/// semi-transparent zone fill.
fn zone_accent_color(
    base: Color32,
    dark_mode: bool,
    brighten: u8,
    alpha_dark: u8,
    alpha_light: u8,
) -> Color32 {
    if dark_mode {
        Color32::from_rgba_unmultiplied(
            base.r().saturating_add(brighten),
            base.g().saturating_add(brighten),
            base.b().saturating_add(brighten),
            alpha_dark,
        )
    } else {
        Color32::from_rgba_unmultiplied(base.r(), base.g(), base.b(), alpha_light)
    }
}

/// Layout a text string into a galley for rendering.
fn layout_text(
    fonts: &mut FontsView,
    text: &str,
    size: f32,
    color: Color32,
    italics: bool,
) -> std::sync::Arc<egui::Galley> {
    let mut job = egui::text::LayoutJob::default();
    job.append(
        text,
        0.0,
        egui::TextFormat {
            font_id: egui::FontId::proportional(size),
            color,
            italics,
            ..Default::default()
        },
    );
    fonts.layout_job(job)
}

/// Custom node shape that displays hostname and IP, with icon based on node type
#[derive(Clone)]
pub struct NetworkNodeShape {
    radius: f32,
    hostname: Option<String>,
    ips: Vec<String>,
    location: Pos2,
    node_type: NodeType,
    /// Subnet zone rendering metadata.
    zone: ZoneDisplay,
}

impl NetworkNodeShape {
    /// Compute node style from payload data.
    fn style_from_payload(payload: &NetworkNode) -> (f32, NodeType, Option<String>, Vec<String>) {
        let radius = calculate_node_radius(payload.flow_count, payload.max_flow_count);
        let ips: Vec<String> = payload.ip_addrs.iter().map(|ip| ip.to_string()).collect();
        (radius, payload.node_type, payload.hostname.clone(), ips)
    }

    /// Sync zone rendering fields from the node payload.
    fn sync_zone_fields(&mut self, p: &NetworkNode) {
        self.zone = p.zone.clone();
    }

    /// Get the image source for this node type.
    fn image_for_node_type(node_type: &NodeType) -> egui::ImageSource<'static> {
        match node_type {
            NodeType::Internet => IMG_INTERNET,
            NodeType::Server => IMG_SERVER,
            NodeType::User => IMG_COMPUTER,
            NodeType::Router => IMG_ROUTER,
        }
    }

    /// Render the node icon at the given position and radius.
    fn render_icon(&self, ctx: &DrawContext, pos: Pos2, radius: f32) -> Vec<Shape> {
        let mut shapes = Vec::new();
        let image_source = Self::image_for_node_type(&self.node_type);
        let size = radius * 2.0;
        let rect = Rect::from_center_size(pos, Vec2::splat(size));

        if let Ok(egui::load::TexturePoll::Ready { texture }) =
            image_source.load(ctx.ctx, TextureOptions::default(), SizeHint::default())
        {
            let uv = Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0));
            let tint = if ctx.ctx.style().visuals.dark_mode {
                COLOR_ICON_TINT_DARK
            } else {
                COLOR_ICON_TINT_LIGHT
            };
            shapes.push(Shape::image(texture.id, rect, uv, tint));
        }

        shapes
    }

    /// Render the node labels (hostname + IPs) below the icon.
    fn render_labels(&self, ctx: &DrawContext, pos: Pos2, radius: f32) -> Vec<Shape> {
        let mut shapes = Vec::new();
        // All sizes below scale with zoom level
        let hostname_size = ctx.meta.canvas_to_screen_size(TEXT_SIZE_DEFAULT);
        let ip_size = ctx.meta.canvas_to_screen_size(TEXT_SIZE_SM);
        let line_spacing = ctx.meta.canvas_to_screen_size(SPACING_XS);
        let mut current_y = pos.y + radius + line_spacing;

        ctx.ctx.fonts_mut(|f| {
            if let Some(ref hostname) = self.hostname {
                // Draw hostname in italic
                let galley = layout_text(f, hostname, hostname_size, COLOR_TEXT_MUTED, true);
                let label_pos = Pos2::new(pos.x - galley.size().x / 2.0, current_y);
                shapes.push(Shape::galley(label_pos, galley, COLOR_TEXT_MUTED));
                current_y += hostname_size + line_spacing;
            }

            // Draw IPs (smaller font) - skip for Internet node
            if self.node_type != NodeType::Internet {
                for ip in &self.ips {
                    let galley = layout_text(f, ip, ip_size, COLOR_TEXT_MUTED, false);
                    let label_pos = Pos2::new(pos.x - galley.size().x / 2.0, current_y);
                    shapes.push(Shape::galley(label_pos, galley, COLOR_TEXT_MUTED));
                    current_y += ip_size + line_spacing;
                }
            }
        });

        shapes
    }

    /// Render a filled rounded rectangle behind the nodes for this subnet zone.
    fn render_zone_background(&self, ctx: &DrawContext) -> Vec<Shape> {
        let mut shapes = Vec::new();
        let center = ctx.meta.canvas_to_screen_pos(self.zone.center);
        let half_w = ctx.meta.canvas_to_screen_size(self.zone.half_size.x);
        let half_h = ctx.meta.canvas_to_screen_size(self.zone.half_size.y);
        let dark_mode = ctx.ctx.style().visuals.dark_mode;
        let color = subnet_zone_color(self.zone.color_idx, dark_mode, self.zone.subnet_mode);

        let rect = Rect::from_center_size(center, Vec2::new(half_w * 2.0, half_h * 2.0));
        let rounding = ctx.meta.canvas_to_screen_size(ZONE_RECT_ROUNDING);

        shapes.push(Shape::rect_filled(rect, rounding, color));

        // Accent color: brighten in dark mode, keep original in light mode
        let accent_color = zone_accent_color(
            color,
            dark_mode,
            ZONE_ACCENT_BRIGHTEN,
            ZONE_ACCENT_ALPHA_DARK,
            ZONE_ACCENT_ALPHA_LIGHT,
        );
        shapes.push(Shape::rect_stroke(
            rect,
            rounding,
            egui::Stroke::new(ZONE_BORDER_STROKE_WIDTH, accent_color),
            StrokeKind::Outside,
        ));

        // Zone label (subnet name + CIDR) above the rectangle
        if let Some(ref label) = self.zone.label {
            let font_size = ctx.meta.canvas_to_screen_size(TEXT_SIZE_SM);

            ctx.ctx.fonts_mut(|f| {
                let galley = layout_text(f, label, font_size, accent_color, false);
                let label_pos = Pos2::new(
                    rect.left() + ctx.meta.canvas_to_screen_size(SPACING_XS),
                    rect.top() - galley.size().y - ctx.meta.canvas_to_screen_size(SPACING_XS),
                );
                shapes.push(Shape::galley(label_pos, galley, accent_color));
            });
        }

        shapes
    }
}

impl From<NodeProps<NetworkNode>> for NetworkNodeShape {
    fn from(props: NodeProps<NetworkNode>) -> Self {
        let (radius, node_type, hostname, ips) = Self::style_from_payload(&props.payload);
        let mut shape = Self {
            radius,
            hostname,
            ips,
            location: props.location(),
            node_type,
            zone: ZoneDisplay::default(),
        };
        shape.sync_zone_fields(&props.payload);
        shape
    }
}

impl DisplayNode<NetworkNode, NetworkEdge, petgraph::Undirected, petgraph::stable_graph::DefaultIx>
    for NetworkNodeShape
{
    /// Determines where edges should connect to the node shape
    fn closest_boundary_point(&self, dir: Vec2) -> Pos2 {
        if dir.length() == 0.0 {
            self.location
        } else {
            self.location + dir.normalized() * self.radius
        }
    }

    /// Set how a node is drawn in the graph.
    /// A node can be composed of several shapes (zone background, icon, labels).
    fn shapes(&mut self, ctx: &DrawContext) -> Vec<Shape> {
        let mut shapes = Vec::new();
        let pos = ctx.meta.canvas_to_screen_pos(self.location);

        // Draw subnet zone background if this node is the designated zone drawer
        if self.zone.draws_zone {
            shapes.extend(self.render_zone_background(ctx));
        }

        let radius = ctx.meta.canvas_to_screen_size(self.radius);
        shapes.extend(self.render_icon(ctx, pos, radius));
        shapes.extend(self.render_labels(ctx, pos, radius));

        shapes
    }

    fn update(&mut self, state: &NodeProps<NetworkNode>) {
        let (radius, node_type, hostname, ips) = Self::style_from_payload(&state.payload);
        self.radius = radius;
        self.node_type = node_type;
        self.hostname = hostname;
        self.ips = ips;
        self.location = state.location();
        self.sync_zone_fields(&state.payload);
    }

    /// Defines the zone where we can click to drag the node
    fn is_inside(&self, pos: Pos2) -> bool {
        pos.distance(self.location) <= self.radius
    }
}

/// Get edge style: (color, width, arrow_start, arrow_end)
/// Edges with flow_count == 0 and Inactive state are invisible (no visual representation).
fn edge_style(edge_data: &NetworkEdge) -> (Color32, f32, bool, bool) {
    match &edge_data.state {
        EdgeState::Inactive => {
            if edge_data.flow_count == 0 {
                // Zero-flow edge: hide
                return (Color32::TRANSPARENT, 0.0, false, false);
            }
            // Thin solid gray if this edge has been active at least once in the past
            let width = calculate_edge_width(edge_data.flow_count, edge_data.max_flow_count);
            (COLOR_EDGE_INACTIVE, width, false, false)
        }
        EdgeState::Active {
            protocol,
            direction,
            ..
        } => {
            let color = color_for_protocol(protocol);
            let (arrow_start, arrow_end) = match direction {
                LinkDirection::Forward => (false, true),
                LinkDirection::Backward => (true, false),
                LinkDirection::Bidirectional => (true, true),
            };
            (color, EDGE_WIDTH_MAX, arrow_start, arrow_end)
        }
    }
}

/// Custom edge shape that uses color/width/arrows based on protocol and direction state
#[derive(Clone)]
pub struct NetworkEdgeShape {
    color: Color32,
    width: f32,
    arrow_start: bool,
    arrow_end: bool,
}

impl From<egui_graphs::EdgeProps<NetworkEdge>> for NetworkEdgeShape {
    fn from(props: egui_graphs::EdgeProps<NetworkEdge>) -> Self {
        let (color, width, arrow_start, arrow_end) = edge_style(&props.payload);
        Self {
            color,
            width,
            arrow_start,
            arrow_end,
        }
    }
}

// Defines an arrow shape to use at the ends of an Edge
fn arrow_head(from: Pos2, to: Pos2, size: f32, angle: f32, color: Color32) -> Shape {
    let dir = (from - to).normalized();
    let p1 = to + Vec2::angled(dir.angle() + angle) * size;
    let p2 = to + Vec2::angled(dir.angle() - angle) * size;
    Shape::convex_polygon(vec![to, p1, p2], color, egui::Stroke::NONE)
}

impl
    DisplayEdge<
        NetworkNode,
        NetworkEdge,
        petgraph::Undirected,
        petgraph::stable_graph::DefaultIx,
        NetworkNodeShape,
    > for NetworkEdgeShape
{
    fn shapes(
        &mut self,
        start: &Node<
            NetworkNode,
            NetworkEdge,
            petgraph::Undirected,
            petgraph::stable_graph::DefaultIx,
            NetworkNodeShape,
        >,
        end: &Node<
            NetworkNode,
            NetworkEdge,
            petgraph::Undirected,
            petgraph::stable_graph::DefaultIx,
            NetworkNodeShape,
        >,
        ctx: &DrawContext,
    ) -> Vec<Shape> {
        // Zero-flow edges produce no shapes
        if self.width == 0.0 {
            return vec![];
        }

        let start_center = start.location();
        let end_center = end.location();
        let dir = end_center - start_center;

        let start_boundary = start.display().closest_boundary_point(dir);
        let end_boundary = end.display().closest_boundary_point(-dir);

        let start_pos = ctx.meta.canvas_to_screen_pos(start_boundary);
        let end_pos = ctx.meta.canvas_to_screen_pos(end_boundary);

        let stroke = egui::Stroke::new(ctx.meta.canvas_to_screen_size(self.width), self.color);

        let mut shapes = vec![Shape::line_segment([start_pos, end_pos], stroke)];

        let arrow_size = ctx.meta.canvas_to_screen_size(EDGE_ARROW_SIZE);
        let arrow_angle = EDGE_ARROW_ANGLE_RAD;
        // Extend arrow tip past the line to avoid square appearance due to line width
        let arrow_tip_offset = ctx.meta.canvas_to_screen_size(self.width);

        if self.arrow_end {
            let dir = (end_pos - start_pos).normalized();
            let extended_end = end_pos + dir * arrow_tip_offset;
            shapes.push(arrow_head(
                start_pos,
                extended_end,
                arrow_size,
                arrow_angle,
                self.color,
            ));
        }
        if self.arrow_start {
            let dir = (start_pos - end_pos).normalized();
            let extended_start = start_pos + dir * arrow_tip_offset;
            shapes.push(arrow_head(
                end_pos,
                extended_start,
                arrow_size,
                arrow_angle,
                self.color,
            ));
        }

        shapes
    }

    fn update(&mut self, state: &egui_graphs::EdgeProps<NetworkEdge>) {
        let (color, width, arrow_start, arrow_end) = edge_style(&state.payload);
        self.color = color;
        self.width = width;
        self.arrow_start = arrow_start;
        self.arrow_end = arrow_end;
    }

    fn is_inside(
        &self,
        start: &Node<
            NetworkNode,
            NetworkEdge,
            petgraph::Undirected,
            petgraph::stable_graph::DefaultIx,
            NetworkNodeShape,
        >,
        end: &Node<
            NetworkNode,
            NetworkEdge,
            petgraph::Undirected,
            petgraph::stable_graph::DefaultIx,
            NetworkNodeShape,
        >,
        pos: Pos2,
    ) -> bool {
        let start_pos = start.location();
        let end_pos = end.location();
        let line_vec = end_pos - start_pos;
        let point_vec = pos - start_pos;

        let line_len = line_vec.length();
        if line_len == 0.0 {
            return false;
        }

        let projection = point_vec.dot(line_vec) / line_len;
        if projection < 0.0 || projection > line_len {
            return false;
        }

        let closest_point = start_pos + line_vec.normalized() * projection;
        closest_point.distance(pos) < self.width
    }
}
