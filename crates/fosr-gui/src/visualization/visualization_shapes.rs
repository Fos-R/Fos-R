//! Custom node and edge shapes for network visualization

use crate::visualization::visualization_tab::{EdgeData, LinkDirection, NodeData, NodeType};
use eframe::egui;
use egui::{Color32, Pos2, Shape, Vec2};
use egui_graphs::{DisplayEdge, DisplayNode, DrawContext, Node, NodeProps};
use fosr_lib::L7Proto;

// Color constants for node types
pub const COLOR_SERVER: Color32 = Color32::from_rgb(46, 204, 113); // Green
pub const COLOR_USER: Color32 = Color32::from_rgb(52, 152, 219); // Blue
pub const COLOR_INTERNET: Color32 = Color32::from_rgb(231, 76, 60); // Red

// Color constants for edge states
pub const COLOR_INACTIVE: Color32 = Color32::from_rgb(200, 200, 200); // Light gray
pub const COLOR_HTTP: Color32 = Color32::from_rgb(52, 152, 219); // Blue
pub const COLOR_HTTPS: Color32 = Color32::from_rgb(46, 204, 113); // Green
pub const COLOR_SSH: Color32 = Color32::from_rgb(155, 89, 182); // Purple
pub const COLOR_DNS: Color32 = Color32::from_rgb(230, 126, 34); // Orange

const RADIUS_NORMAL: f32 = 20.0;
const RADIUS_INTERNET: f32 = 30.0;

const EDGE_WIDTH_INACTIVE: f32 = 0.5;
const EDGE_WIDTH_ACTIVE: f32 = 3.0;

/// Custom node shape that displays hostname and IP, with color based on node type
#[derive(Clone)]
pub struct NetworkNodeShape {
    radius: f32,
    color: Color32,
    label: String,
    location: Pos2,
    is_internet: bool,
}

impl From<NodeProps<NodeData>> for NetworkNodeShape {
    fn from(props: NodeProps<NodeData>) -> Self {
        let payload = &props.payload;
        let (color, radius, is_internet) = match payload.node_type {
            NodeType::Server => (COLOR_SERVER, RADIUS_NORMAL, false),
            NodeType::User => (COLOR_USER, RADIUS_NORMAL, false),
            NodeType::Internet => (COLOR_INTERNET, RADIUS_INTERNET, true),
        };

        let label = if let Some(ref hostname) = payload.hostname {
            if payload.node_type == NodeType::Internet {
                hostname.clone()
            } else {
                format!("{}\n{}", hostname, payload.ip_addr)
            }
        } else {
            format!("{}", payload.ip_addr)
        };

        Self {
            radius,
            color,
            label,
            location: props.location(),
            is_internet,
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

        // Draw filled circle
        shapes.push(Shape::circle_filled(pos, radius, self.color));

        // Draw circle stroke (thicker for Internet node)
        let stroke_width = if self.is_internet { 2.5 } else { 1.5 };
        shapes.push(Shape::circle_stroke(
            pos,
            radius,
            egui::Stroke::new(stroke_width, Color32::DARK_GRAY),
        ));

        // Draw text label
        let font_size = if self.is_internet { 14.0 } else { 10.0 };
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
        let payload = &state.payload;

        let (color, radius, is_internet) = match payload.node_type {
            NodeType::Server => (COLOR_SERVER, RADIUS_NORMAL, false),
            NodeType::User => (COLOR_USER, RADIUS_NORMAL, false),
            NodeType::Internet => (COLOR_INTERNET, RADIUS_INTERNET, true),
        };

        self.color = color;
        self.radius = radius;
        self.is_internet = is_internet;

        self.label = if let Some(ref hostname) = payload.hostname {
            if payload.node_type == NodeType::Internet {
                hostname.clone()
            } else {
                format!("{}\n{}", hostname, payload.ip_addr)
            }
        } else {
            format!("{}", payload.ip_addr)
        };

        self.location = state.location();
    }

    /// Defines the zone where we can click to drag the node
    fn is_inside(&self, pos: Pos2) -> bool {
        pos.distance(self.location) <= self.radius
    }
}

/// Get edge style based on protocol and direction
fn edge_style(edge_data: &EdgeData) -> (Color32, f32, bool, bool) {
    match edge_data {
        EdgeData::Inactive => (COLOR_INACTIVE, EDGE_WIDTH_INACTIVE, false, false),
        EdgeData::Active { protocol, direction, .. } => {
            let color = match protocol {
                L7Proto::HTTP => Color32::from_rgb(52, 152, 219),  // Blue
                L7Proto::HTTPS => Color32::from_rgb(46, 204, 113), // Green
                L7Proto::SSH => Color32::from_rgb(155, 89, 182),   // Purple
                L7Proto::DNS => Color32::from_rgb(230, 126, 34),   // Orange
                _ => Color32::from_rgb(149, 165, 166),             // Gray
            };
            let (arrow_start, arrow_end) = match direction {
                LinkDirection::Forward => (false, true),
                LinkDirection::Backward => (true, false),
                LinkDirection::Bidirectional => (true, true),
            };
            (color, EDGE_WIDTH_ACTIVE, arrow_start, arrow_end)
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

        if self.arrow_end {
            shapes.push(arrow_head(start_pos, end_pos, arrow_size, arrow_angle, self.color));
        }
        if self.arrow_start {
            shapes.push(arrow_head(end_pos, start_pos, arrow_size, arrow_angle, self.color));
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
