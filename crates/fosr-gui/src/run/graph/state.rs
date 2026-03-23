//! Visualization state: graph data, active links, flow processing, and export.

use super::shapes::{NetworkEdgeShape, NetworkNodeShape};
use super::stream::{FlowEvent, FlowStreamer};
use super::utils::distribute_nodes_circle;
use crate::shared::config::model::Host;
use crate::shared::constants::ui::DELAY_FRAMES_QUICK;
use eframe::egui;
use egui_graphs::events::Event;
use fosr_lib::{L7Proto, OS, config, config::HostType};
use petgraph::graph::NodeIndex;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::Ipv4Addr;
use std::rc::Rc;
use std::sync::mpsc::Receiver;
use std::sync::{Arc, RwLock};
use web_time::Instant;

/// Special IP address representing "The Internet" node
pub const INTERNET_IP: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 1);

/// Node type for visualization (extends HostType with Internet)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeType {
    Server,
    User,
    Internet,
}

impl From<HostType> for NodeType {
    fn from(host_type: HostType) -> Self {
        match host_type {
            HostType::Server => NodeType::Server,
            HostType::User => NodeType::User,
        }
    }
}

/// Node data: host information
#[derive(Clone, Debug)]
pub struct NodeData {
    pub ip_addrs: Vec<Ipv4Addr>,
    pub hostname: Option<String>,
    pub node_type: NodeType,
    #[allow(dead_code)] // Kept for possible future use (node styling by OS?)
    pub os: OS,
    /// Number of flows this node has been involved in (as sender or receiver).
    /// Used for dynamic node sizing - more active nodes appear larger.
    pub flow_count: u32,
    /// Maximum flow count among all nodes (for proportional sizing).
    /// When the linear formula would exceed RADIUS_MAX, we switch to proportional mode.
    pub max_flow_count: u32,
}

impl NodeData {
    /// Create an Internet node
    pub fn internet() -> Self {
        Self {
            ip_addrs: vec![INTERNET_IP],
            hostname: Some("Internet".to_string()),
            node_type: NodeType::Internet,
            os: OS::Linux, // Doesn't matter for Internet node
            flow_count: 0,
            max_flow_count: 0,
        }
    }
}

// Display the hostname plus all IP addresses
impl fmt::Display for NodeData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref hostname) = self.hostname {
            if self.node_type == NodeType::Internet {
                write!(f, "{}", hostname)
            } else {
                // Display hostname followed by all IPs (one per line)
                let ips_str = self
                    .ip_addrs
                    .iter()
                    .map(|ip| ip.to_string())
                    .collect::<Vec<_>>()
                    .join("\n");
                write!(f, "{}\n{}", hostname, ips_str)
            }
        } else {
            // No hostname: display all IPs (one per line)
            let ips_str = self
                .ip_addrs
                .iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>()
                .join("\n");
            write!(f, "{}", ips_str)
        }
    }
}

/// Edge data: communication state with cumulative flow count for thickness
#[derive(Clone, Debug)]
pub struct EdgeData {
    /// Current visual state (active with protocol or inactive)
    pub state: EdgeState,
    /// Cumulative flow count - persists even when inactive, used for edge thickness
    pub flow_count: u32,
    /// Maximum flow count among all edges (for proportional sizing)
    pub max_flow_count: u32,
}

impl Default for EdgeData {
    fn default() -> Self {
        Self {
            state: EdgeState::Inactive,
            flow_count: 0,
            max_flow_count: 0,
        }
    }
}

/// Visual state of an edge
#[derive(Clone, Debug, Default)]
pub enum EdgeState {
    #[default]
    Inactive,
    Active {
        protocol: L7Proto,
        #[allow(dead_code)] // Kept for possible future animation effects?
        start_time: Instant,
        direction: LinkDirection,
    },
}

impl fmt::Display for EdgeData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.state {
            EdgeState::Inactive => write!(f, ""),
            EdgeState::Active { protocol, .. } => write!(f, "{:?}", protocol),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum LinkDirection {
    Forward,
    Backward,
    Bidirectional,
}

/// An active link being displayed
pub struct ActiveLink {
    pub protocol: L7Proto,
    pub start_time: Instant,
    pub direction: LinkDirection,
}

pub type VisualizationGraph = egui_graphs::Graph<
    NodeData,
    EdgeData,
    petgraph::Undirected,
    petgraph::stable_graph::DefaultIx,
    NetworkNodeShape,
    NetworkEdgeShape,
>;

/// State machine for screenshot export
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScreenshotStateMachine {
    #[default]
    Idle,
    /// Hide overlays on next frame before taking screenshot
    HidingOverlays,
    /// Screenshot requested, waiting for result
    WaitingForScreenshot,
}

/// Network structure and IP/Node lookups
pub struct NetworkData {
    pub graph: VisualizationGraph,
    pub known_ips: HashSet<Ipv4Addr>,
    pub ip_to_node: HashMap<Ipv4Addr, NodeIndex>,
    pub node_to_host: HashMap<NodeIndex, usize>,
}

impl Default for NetworkData {
    fn default() -> Self {
        Self {
            graph: VisualizationGraph::new(petgraph::stable_graph::StableGraph::default()),
            known_ips: HashSet::new(),
            ip_to_node: HashMap::new(),
            node_to_host: HashMap::new(),
        }
    }
}

/// Flow processing and streaming state
pub struct FlowState {
    pub receiver: Option<Receiver<FlowEvent>>,
    pub active_links: HashMap<(Ipv4Addr, Ipv4Addr), ActiveLink>,
    pub streamer: Option<FlowStreamer>,
    pub running: bool,
    pub speed: Arc<RwLock<f32>>,
    pub total_flows: u32,
    pub visualization_start: Option<Instant>,
}

impl Default for FlowState {
    fn default() -> Self {
        Self {
            receiver: None,
            active_links: HashMap::new(),
            streamer: None,
            running: false,
            speed: Arc::new(RwLock::new(1.0)),
            total_flows: 0,
            visualization_start: None,
        }
    }
}

/// Layout and rendering state
pub struct ViewState {
    pub layout_initialized: bool,
    pub reset_requested: bool,
    pub delayed_fit_countdown: Option<u8>,
    pub last_screen_size: Option<egui::Vec2>,
    pub graph_rect: Option<egui::Rect>,
}

impl Default for ViewState {
    fn default() -> Self {
        Self {
            layout_initialized: false,
            reset_requested: false,
            delayed_fit_countdown: Some(DELAY_FRAMES_QUICK), // Delay initial fit for bottom panel
            last_screen_size: None,
            graph_rect: None,
        }
    }
}

/// Node info modal state
pub struct ModalState {
    pub events_buffer: Rc<RefCell<Vec<Event>>>,
    pub clicked_node: Option<NodeIndex>,
    pub open: bool,
    pub edit_buffer: Option<Host>,
}

impl Default for ModalState {
    fn default() -> Self {
        Self {
            events_buffer: Rc::new(RefCell::new(Vec::new())),
            clicked_node: None,
            open: false,
            edit_buffer: None,
        }
    }
}

/// Represents the state of the visualization tab.
pub struct VisualizationState {
    /// Network structure and lookups
    pub network: NetworkData,
    /// Flow processing and streaming
    pub flow: FlowState,
    /// Layout and rendering
    pub view: ViewState,
    /// Node info modal
    pub modal: ModalState,
    /// Screenshot export state machine
    pub screenshot_export: ScreenshotStateMachine,
    /// Config content tracking (for detecting changes)
    pub config_content: Option<String>,
    /// Auto-start countdown frames
    pub auto_start_countdown: Option<u8>,
    /// Whether user has manually started visualization
    pub user_has_started: bool,
}

impl Default for VisualizationState {
    fn default() -> Self {
        Self {
            network: NetworkData::default(),
            flow: FlowState::default(),
            view: ViewState::default(),
            modal: ModalState::default(),
            screenshot_export: ScreenshotStateMachine::default(),
            config_content: None,
            auto_start_countdown: None,
            user_has_started: false,
        }
    }
}

impl VisualizationState {
    /// Update state from a configuration (preserves some state)
    /// Note: caller should stop visualization before calling this if running
    pub fn update_from_config(&mut self, config: &config::Configuration) {
        let (graph, known_ips, ip_to_node, node_to_host) = Self::build_graph_from_config(config);
        self.network.graph = graph;
        self.network.known_ips = known_ips;
        self.network.ip_to_node = ip_to_node;
        self.network.node_to_host = node_to_host;
        self.view.layout_initialized = false;
    }

    /// Build graph from configuration (shared logic)
    fn build_graph_from_config(
        config: &config::Configuration,
    ) -> (
        VisualizationGraph,
        HashSet<Ipv4Addr>,
        HashMap<Ipv4Addr, NodeIndex>,
        HashMap<NodeIndex, usize>,
    ) {
        let mut graph = VisualizationGraph::new(petgraph::stable_graph::StableGraph::default());
        let mut known_ips = HashSet::new();
        let mut ip_to_node: HashMap<Ipv4Addr, NodeIndex> = HashMap::new();
        let mut node_to_host: HashMap<NodeIndex, usize> = HashMap::new();

        // Add one node per host (with all its IPs)
        for (host_idx, host) in config.get_hosts().iter().enumerate() {
            let all_ips: Vec<Ipv4Addr> = host.interfaces.iter().map(|i| i.ip_addr).collect();

            let node_data = NodeData {
                ip_addrs: all_ips.clone(),
                hostname: host.hostname.clone(),
                node_type: host.host_type.into(),
                os: host.os,
                flow_count: 0,
                max_flow_count: 0,
            };
            let idx = graph.add_node_with_location(node_data, egui::pos2(0.0, 0.0));
            node_to_host.insert(idx, host_idx);

            // Map all IPs of this host to the same node
            for ip in all_ips {
                known_ips.insert(ip);
                ip_to_node.insert(ip, idx);
            }
        }

        // Distribute nodes before adding the Internet node, so that it stays in the center
        distribute_nodes_circle(&mut graph);

        // Add Internet node
        let internet_idx = graph.add_node_with_location(NodeData::internet(), egui::pos2(0.0, 0.0));
        ip_to_node.insert(INTERNET_IP, internet_idx);

        // Add edges for all possible connections between users and servers
        for &user_ip in &config.users {
            if let Some(&user_idx) = ip_to_node.get(&user_ip) {
                for &server_ip in &config.servers {
                    if let Some(&server_idx) = ip_to_node.get(&server_ip) {
                        graph.add_edge(user_idx, server_idx, EdgeData::default());
                    }
                }
                // Add edge to Internet for each user
                graph.add_edge(user_idx, internet_idx, EdgeData::default());
            }
        }

        // Add edges from servers to Internet
        for &server_ip in &config.servers {
            if let Some(&server_idx) = ip_to_node.get(&server_ip) {
                graph.add_edge(server_idx, internet_idx, EdgeData::default());
            }
        }

        (graph, known_ips, ip_to_node, node_to_host)
    }

    /// Check if an IP is a known (configured) IP
    pub fn is_known_ip(&self, ip: Ipv4Addr) -> bool {
        self.network.known_ips.contains(&ip)
    }

    /// Reset all flow counts on nodes and edges
    fn reset_flow_counts(&mut self) {
        self.flow.total_flows = 0;
        for idx in self.network.graph.g().node_indices().collect::<Vec<_>>() {
            if let Some(node) = self.network.graph.g_mut().node_weight_mut(idx) {
                let payload = node.payload_mut();
                payload.flow_count = 0;
                payload.max_flow_count = 0;
            }
        }
        for idx in self.network.graph.g().edge_indices().collect::<Vec<_>>() {
            if let Some(edge) = self.network.graph.g_mut().edge_weight_mut(idx) {
                let payload = edge.payload_mut();
                payload.flow_count = 0;
                payload.max_flow_count = 0;
            }
        }
    }

    /// Start visualization
    /// If config_content is None, the FlowStreamer uses the default BN model (no config applied)
    /// Speed controls how fast flows are emitted (1.0 = real-time, 2.0 = 2x faster) - can be updated at runtime via slider
    /// If reset is true, flow counts are reset to zero before starting
    pub fn start_visualization(
        &mut self,
        config_content: Option<&str>,
        speed: Arc<RwLock<f32>>,
        reset: bool,
    ) -> Result<(), String> {
        if reset {
            self.reset_flow_counts();
        }

        log::debug!(
            "Starting visualization with {} known IPs:",
            self.network.known_ips.len()
        );
        for ip in &self.network.known_ips {
            log::debug!("  - {}", ip);
        }

        let (sender, receiver) = std::sync::mpsc::channel();

        let streamer = FlowStreamer::new(config_content, speed.clone(), sender)?;
        streamer.start();

        self.flow.streamer = Some(streamer);
        self.flow.receiver = Some(receiver);
        self.flow.running = true;
        self.flow.visualization_start = Some(Instant::now());
        log::info!(
            "Flow visualization started (config: {}, speed: {}x)",
            if config_content.is_some() {
                "user-provided"
            } else {
                "default BN model"
            },
            *speed.read().unwrap()
        );

        Ok(())
    }

    /// Stop visualization
    pub fn stop_visualization(&mut self) {
        self.flow.running = false;
        if let Some(streamer) = &self.flow.streamer {
            streamer.stop();
        }
        self.flow.streamer = None;
        self.flow.receiver = None;
        self.flow.active_links.clear();
        self.flow.visualization_start = None;
        log::info!("Flow visualization stopped");
    }
}
