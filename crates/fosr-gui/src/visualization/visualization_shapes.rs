//! Custom node and edge shapes for network visualization

use crate::visualization::visualization_tab::{EdgeData, EdgeState, LinkDirection, NodeData, NodeType};
use eframe::egui;
use egui::{Color32, Pos2, Rect, Shape, TextureOptions, Vec2, load::SizeHint};
use egui_graphs::{DisplayEdge, DisplayNode, DrawContext, Node, NodeProps};
use fosr_lib::L7Proto;

// Embedded node images
const IMG_SERVER: egui::ImageSource = egui::include_image!("../../assets/server.png");
const IMG_COMPUTER: egui::ImageSource = egui::include_image!("../../assets/computer.png");
const IMG_INTERNET: egui::ImageSource = egui::include_image!("../../assets/internet.png");

// Icon tint: gray instead of pure black/white
pub const ICON_TINT_DARK: Color32 = Color32::from_rgb(180, 180, 180);
pub const ICON_TINT_LIGHT: Color32 = Color32::from_rgb(40, 40, 40);

// Color constants for edge states
pub const COLOR_INACTIVE: Color32 = Color32::from_rgb(200, 200, 200); // Light gray
pub const COLOR_HTTP: Color32 = Color32::from_rgb(52, 152, 219); // Blue
pub const COLOR_HTTPS: Color32 = Color32::from_rgb(46, 204, 113); // Green
pub const COLOR_SSH: Color32 = Color32::from_rgb(155, 89, 182); // Purple
pub const COLOR_DNS: Color32 = Color32::from_rgb(230, 126, 34); // Orange
pub const COLOR_SMTP: Color32 = Color32::from_rgb(241, 196, 15); // Yellow
pub const COLOR_OTHER: Color32 = Color32::from_rgb(149, 165, 166); // Gray

// Node radius constants - all nodes grow with flow count
const RADIUS_MIN: f32 = 15.0;      // Starting size for all nodes
const RADIUS_MAX: f32 = 25.0;       // Maximum size
const FLOW_SCALE_FACTOR: f32 = 0.3; // Radius increase per flow

const EDGE_WIDTH_MIN: f32 = 0.0;
const EDGE_WIDTH_MAX: f32 = 3.0;
const EDGE_FLOW_SCALE: f32 = 0.2; // Width increase per flow (linear phase)

/// Custom node shape that displays hostname and IP, with icon based on node type
#[derive(Clone)]
pub struct NetworkNodeShape {
    radius: f32,
    label: String,
    location: Pos2,
    node_type: NodeType,
}

impl NetworkNodeShape {
    /// Compute node style from payload data.
    fn style_from_payload(payload: &NodeData) -> (f32, NodeType, String) {
        // Hybrid linear/proportional radius scaling
        let max_linear = RADIUS_MIN + payload.max_flow_count as f32 * FLOW_SCALE_FACTOR;
        let radius = if max_linear < RADIUS_MAX {
            // Linear phase: everyone grows normally
            RADIUS_MIN + payload.flow_count as f32 * FLOW_SCALE_FACTOR
        } else {
            // Proportional phase: scale by ratio to max
            let ratio = if payload.max_flow_count > 0 {
                payload.flow_count as f32 / payload.max_flow_count as f32
            } else {
                0.0
            };
            RADIUS_MIN + ratio * (RADIUS_MAX - RADIUS_MIN)
        };

        (radius, payload.node_type.clone(), payload.to_string())
    }

    /// Get the image source for this node type
    fn image_for_node_type(node_type: &NodeType) -> egui::ImageSource<'static> {
        match node_type {
            NodeType::Internet => IMG_INTERNET,
            NodeType::Server => IMG_SERVER,
            NodeType::User => IMG_COMPUTER,
        }
    }
}

impl From<NodeProps<NodeData>> for NetworkNodeShape {
    fn from(props: NodeProps<NodeData>) -> Self {
        let (radius, node_type, label) = Self::style_from_payload(&props.payload);
        Self {
            radius,
            label,
            location: props.location(),
            node_type,
        }
    }
}

impl DisplayNode<NodeData, EdgeData, petgraph::Undirected, petgraph::stable_graph::DefaultIx>
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

    /// Set how a node is drawn in the graph
    /// A node can be composed of several shapes
    fn shapes(&mut self, ctx: &DrawContext) -> Vec<Shape> {
        let mut shapes = Vec::new();
        let pos = ctx.meta.canvas_to_screen_pos(self.location);
        let radius = ctx.meta.canvas_to_screen_size(self.radius);

        // Load and draw node icon
        let image_source = Self::image_for_node_type(&self.node_type);
        let size = radius * 2.0;
        let rect = Rect::from_center_size(pos, Vec2::splat(size));

        if let Ok(egui::load::TexturePoll::Ready { texture }) =
            image_source.load(ctx.ctx, TextureOptions::default(), SizeHint::default())
        {
            let uv = Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0));
            let tint = if ctx.ctx.style().visuals.dark_mode {
                ICON_TINT_DARK
            } else {
                ICON_TINT_LIGHT
            };
            shapes.push(Shape::image(texture.id, rect, uv, tint));
        }

        // Draw text label
        let is_internet = matches!(self.node_type, NodeType::Internet);
        let font_size = if is_internet { 14.0 } else { 10.0 };
        let font_id = egui::FontId::proportional(font_size);

        let job = egui::text::LayoutJob::simple(
            self.label.clone(),
            font_id,
            Color32::GRAY,
            f32::INFINITY,
        );

        ctx.ctx.fonts_mut(|f| {
            let galley = f.layout_job(job);
            let label_pos = Pos2::new(pos.x - galley.size().x / 2.0, pos.y + radius + 2.0);
            shapes.push(Shape::galley(label_pos, galley, Color32::GRAY));
        });

        shapes
    }

    fn update(&mut self, state: &NodeProps<NodeData>) {
        let (radius, node_type, label) = Self::style_from_payload(&state.payload);
        self.radius = radius;
        self.node_type = node_type;
        self.label = label;
        self.location = state.location();
    }

    /// Defines the zone where we can click to drag the node
    fn is_inside(&self, pos: Pos2) -> bool {
        pos.distance(self.location) <= self.radius
    }
}

/// Get edge style based on protocol, direction, and flow count
fn edge_style(edge_data: &EdgeData) -> (Color32, f32, bool, bool) {
    match &edge_data.state {
        EdgeState::Inactive => {
            // Hybrid linear/proportional width scaling (same approach as nodes)
            let max_linear = EDGE_WIDTH_MIN + edge_data.max_flow_count as f32 * EDGE_FLOW_SCALE;
            let width = if max_linear < EDGE_WIDTH_MAX {
                // Linear phase: all edges grow normally
                EDGE_WIDTH_MIN + edge_data.flow_count as f32 * EDGE_FLOW_SCALE
            } else {
                // Proportional phase: scale by ratio to max
                let ratio = if edge_data.max_flow_count > 0 {
                    edge_data.flow_count as f32 / edge_data.max_flow_count as f32
                } else {
                    0.0
                };
                EDGE_WIDTH_MIN + ratio * (EDGE_WIDTH_MAX - EDGE_WIDTH_MIN)
            };
            (COLOR_INACTIVE, width, false, false)
        }
        EdgeState::Active { protocol, direction, .. } => {
            let color = match protocol {
                L7Proto::HTTP => COLOR_HTTP,
                L7Proto::HTTPS => COLOR_HTTPS,
                L7Proto::SSH => COLOR_SSH,
                L7Proto::DNS => COLOR_DNS,
                L7Proto::SMTP => COLOR_SMTP,
                _ => COLOR_OTHER,
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

impl From<egui_graphs::EdgeProps<EdgeData>> for NetworkEdgeShape {
    fn from(props: egui_graphs::EdgeProps<EdgeData>) -> Self {
        let (color, width, arrow_start, arrow_end) = edge_style(&props.payload);
        Self { color, width, arrow_start, arrow_end }
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
    NodeData,
    EdgeData,
    petgraph::Undirected,
    petgraph::stable_graph::DefaultIx,
    NetworkNodeShape,
> for NetworkEdgeShape
{
    fn shapes(
        &mut self,
        start: &Node<
            NodeData,
            EdgeData,
            petgraph::Undirected,
            petgraph::stable_graph::DefaultIx,
            NetworkNodeShape,
        >,
        end: &Node<
            NodeData,
            EdgeData,
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

        let arrow_size = ctx.meta.canvas_to_screen_size(16.0);
        let arrow_angle = std::f32::consts::PI / 6.0;
        // Extend arrow tip past the line to avoid square appearance due to line width
        let arrow_tip_offset = ctx.meta.canvas_to_screen_size(self.width);

        if self.arrow_end {
            let dir = (end_pos - start_pos).normalized();
            let extended_end = end_pos + dir * arrow_tip_offset;
            shapes.push(arrow_head(start_pos, extended_end, arrow_size, arrow_angle, self.color));
        }
        if self.arrow_start {
            let dir = (start_pos - end_pos).normalized();
            let extended_start = start_pos + dir * arrow_tip_offset;
            shapes.push(arrow_head(end_pos, extended_start, arrow_size, arrow_angle, self.color));
        }

        shapes
    }

    fn update(&mut self, state: &egui_graphs::EdgeProps<EdgeData>) {
        let (color, width, arrow_start, arrow_end) = edge_style(&state.payload);
        self.color = color;
        self.width = width;
        self.arrow_start = arrow_start;
        self.arrow_end = arrow_end;
    }

    fn is_inside(
        &self,
        start: &Node<
            NodeData,
            EdgeData,
            petgraph::Undirected,
            petgraph::stable_graph::DefaultIx,
            NetworkNodeShape,
        >,
        end: &Node<
            NodeData,
            EdgeData,
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
