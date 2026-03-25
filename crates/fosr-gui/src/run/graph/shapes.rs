//! Custom node and edge shapes with protocol colors, icons, and dynamic sizing.
//!
//! egui_graphs rendering:
//! - `DisplayNode` trait: defines how a node is drawn (shapes, labels, icons)
//! - `DisplayEdge` trait: defines how an edge is drawn (lines, arrows, colors)
//! - `closest_boundary_point`: where edges connect to the node boundary
//! - `is_inside`: hit-testing for clicking and dragging

use super::state::{NetworkEdge, EdgeState, LinkDirection, NetworkNode, NodeType};
use crate::shared::assets::{IMG_COMPUTER, IMG_INTERNET, IMG_SERVER};
use crate::shared::constants::colors::{
    COLOR_EDGE_INACTIVE, COLOR_ICON_TINT_DARK, COLOR_ICON_TINT_LIGHT, COLOR_PROTOCOL_DNS,
    COLOR_PROTOCOL_HTTP, COLOR_PROTOCOL_HTTPS, COLOR_PROTOCOL_OTHER, COLOR_PROTOCOL_SMTP,
    COLOR_PROTOCOL_SSH, COLOR_TEXT_MUTED,
};
use crate::shared::constants::ui::{
    EDGE_ARROW_ANGLE_RAD, EDGE_ARROW_SIZE, EDGE_FLOW_SCALE, EDGE_WIDTH_MAX, EDGE_WIDTH_MIN,
    NODE_FLOW_SCALE_FACTOR, NODE_RADIUS_MAX, NODE_RADIUS_MIN, SPACING_XS, TEXT_SIZE_DEFAULT,
};
use eframe::egui::{self, Color32, Pos2, Rect, Shape, TextureOptions, Vec2, load::SizeHint};
use egui_graphs::{DisplayEdge, DisplayNode, DrawContext, Node, NodeProps};
use fosr_lib::L7Proto;

/// Calculate node radius using hybrid linear/proportional scaling.
///
/// The scaling works in two phases:
/// 1. **Linear phase**: While the maximum possible radius is below `NODE_RADIUS_MAX`,
///    each node grows proportionally to its flow count.
/// 2. **Proportional phase**: Once we would exceed `NODE_RADIUS_MAX`, switch to
///    ratio-based scaling so the most active node is always at max size.
///
/// This ensures nodes grow smoothly at low traffic, but remain comparable at high traffic.
fn calculate_node_radius(flow_count: u32, max_flow_count: u32) -> f32 {
    let max_linear = NODE_RADIUS_MIN + max_flow_count as f32 * NODE_FLOW_SCALE_FACTOR;

    if max_linear < NODE_RADIUS_MAX {
        // Linear phase: everyone grows normally
        NODE_RADIUS_MIN + flow_count as f32 * NODE_FLOW_SCALE_FACTOR
    } else {
        // Proportional phase: scale by ratio to max
        let ratio = if max_flow_count > 0 {
            flow_count as f32 / max_flow_count as f32
        } else {
            0.0
        };
        NODE_RADIUS_MIN + ratio * (NODE_RADIUS_MAX - NODE_RADIUS_MIN)
    }
}

/// Calculate edge width using hybrid linear/proportional scaling.
///
/// Uses the same two-phase approach as `calculate_node_radius`:
/// 1. **Linear phase**: Edges grow proportionally while below `EDGE_WIDTH_MAX`.
/// 2. **Proportional phase**: Ratio-based scaling to keep the busiest edge at max width.
fn calculate_edge_width(flow_count: u32, max_flow_count: u32) -> f32 {
    let max_linear = EDGE_WIDTH_MIN + max_flow_count as f32 * EDGE_FLOW_SCALE;

    if max_linear < EDGE_WIDTH_MAX {
        // Linear phase: all edges grow normally
        EDGE_WIDTH_MIN + flow_count as f32 * EDGE_FLOW_SCALE
    } else {
        // Proportional phase: scale by ratio to max
        let ratio = if max_flow_count > 0 {
            flow_count as f32 / max_flow_count as f32
        } else {
            0.0
        };
        EDGE_WIDTH_MIN + ratio * (EDGE_WIDTH_MAX - EDGE_WIDTH_MIN)
    }
}

/// Custom node shape that displays hostname and IP, with icon based on node type
#[derive(Clone)]
pub struct NetworkNodeShape {
    radius: f32,
    hostname: Option<String>,
    ips: Vec<String>,
    location: Pos2,
    node_type: NodeType,
}

impl NetworkNodeShape {
    /// Compute node style from payload data.
    fn style_from_payload(payload: &NetworkNode) -> (f32, NodeType, Option<String>, Vec<String>) {
        let radius = calculate_node_radius(payload.flow_count, payload.max_flow_count);
        let ips: Vec<String> = payload.ip_addrs.iter().map(|ip| ip.to_string()).collect();
        (
            radius,
            payload.node_type.clone(),
            payload.hostname.clone(),
            ips,
        )
    }

    /// Get the image source for this node type.
    fn image_for_node_type(node_type: &NodeType) -> egui::ImageSource<'static> {
        match node_type {
            NodeType::Internet => IMG_INTERNET,
            NodeType::Server => IMG_SERVER,
            NodeType::User => IMG_COMPUTER,
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
        let font_size = TEXT_SIZE_DEFAULT;
        let font_id = egui::FontId::proportional(font_size);
        let mut current_y = pos.y + radius + SPACING_XS;

        ctx.ctx.fonts_mut(|f| {
            // Draw hostname in italic
            if let Some(ref hostname) = self.hostname {
                let mut job = egui::text::LayoutJob::default();
                job.append(
                    hostname,
                    0.0,
                    egui::TextFormat {
                        font_id: font_id.clone(),
                        color: COLOR_TEXT_MUTED,
                        italics: true,
                        ..Default::default()
                    },
                );
                let galley = f.layout_job(job);
                let label_pos = Pos2::new(pos.x - galley.size().x / 2.0, current_y);
                shapes.push(Shape::galley(label_pos, galley, COLOR_TEXT_MUTED));
                current_y += font_size + SPACING_XS;
            }

            // Draw IPs (normal) - skip for Internet node
            if self.node_type != NodeType::Internet {
                for ip in &self.ips {
                    let mut job = egui::text::LayoutJob::default();
                    job.append(
                        ip,
                        0.0,
                        egui::TextFormat {
                            font_id: font_id.clone(),
                            color: COLOR_TEXT_MUTED,
                            ..Default::default()
                        },
                    );
                    let galley = f.layout_job(job);
                    let label_pos = Pos2::new(pos.x - galley.size().x / 2.0, current_y);
                    shapes.push(Shape::galley(label_pos, galley, COLOR_TEXT_MUTED));
                    current_y += font_size + SPACING_XS;
                }
            }
        });

        shapes
    }
}

impl From<NodeProps<NetworkNode>> for NetworkNodeShape {
    fn from(props: NodeProps<NetworkNode>) -> Self {
        let (radius, node_type, hostname, ips) = Self::style_from_payload(&props.payload);
        Self {
            radius,
            hostname,
            ips,
            location: props.location(),
            node_type,
        }
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
    /// A node can be composed of several shapes (icon + labels).
    fn shapes(&mut self, ctx: &DrawContext) -> Vec<Shape> {
        let mut shapes = Vec::new();
        let pos = ctx.meta.canvas_to_screen_pos(self.location);
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
    }

    /// Defines the zone where we can click to drag the node
    fn is_inside(&self, pos: Pos2) -> bool {
        pos.distance(self.location) <= self.radius
    }
}

/// Get edge style based on protocol, direction, and flow count
fn edge_style(edge_data: &NetworkEdge) -> (Color32, f32, bool, bool) {
    match &edge_data.state {
        EdgeState::Inactive => {
            let width = calculate_edge_width(edge_data.flow_count, edge_data.max_flow_count);
            (COLOR_EDGE_INACTIVE, width, false, false)
        }
        EdgeState::Active {
            protocol,
            direction,
            ..
        } => {
            let color = match protocol {
                L7Proto::HTTP => COLOR_PROTOCOL_HTTP,
                L7Proto::HTTPS => COLOR_PROTOCOL_HTTPS,
                L7Proto::SSH => COLOR_PROTOCOL_SSH,
                L7Proto::DNS => COLOR_PROTOCOL_DNS,
                L7Proto::SMTP => COLOR_PROTOCOL_SMTP,
                _ => COLOR_PROTOCOL_OTHER,
            };
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
        let start_center = start.location();
        let end_center = end.location();
        let dir = end_center - start_center;

        let start_boundary = start.display().closest_boundary_point(dir);
        let end_boundary = end.display().closest_boundary_point(-dir);

        let start_pos = ctx.meta.canvas_to_screen_pos(start_boundary);
        let end_pos = ctx.meta.canvas_to_screen_pos(end_boundary);

        let mut shapes = vec![Shape::line_segment(
            [start_pos, end_pos],
            egui::Stroke::new(ctx.meta.canvas_to_screen_size(self.width), self.color),
        )];

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
