use super::visualization_shapes::{NetworkEdgeShape, NetworkNodeShape};
use super::visualization_stream::{FlowEvent, FlowStreamer};
use super::visualization_utils::distribute_nodes_circle;
use crate::shared::config_model::Host;
use eframe::egui;
use egui_graphs::events::Event;
use fosr_lib::{L7Proto, OS, config, config::HostType};
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

/// Color for stop/danger buttons
pub const STOP_BUTTON_COLOR: egui::Color32 = egui::Color32::from_rgb(200, 80, 80);

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
pub enum ExportState {
    #[default]
    Idle,
    /// Hide overlays on next frame before taking screenshot
    HidingOverlays,
    /// Screenshot requested, waiting for result
    WaitingForScreenshot,
}

/// Represents the state of the visualization tab.
pub struct VisualizationTabState {
    pub graph: VisualizationGraph,
    pub flow_receiver: Option<Receiver<FlowEvent>>,
    pub active_links: HashMap<(Ipv4Addr, Ipv4Addr), ActiveLink>,
    pub visualization_running: bool,
    pub config_content: Option<String>,
    pub streamer: Option<FlowStreamer>,
    pub layout_initialized: bool,
    /// Set of known IPs from the configuration (for filtering Internet flows)
    pub known_ips: HashSet<Ipv4Addr>,
    /// Map from IP to node index for quick lookup
    pub ip_to_node: HashMap<Ipv4Addr, petgraph::graph::NodeIndex>,
    /// Visualization start time (for timestamp-based flow display)
    pub visualization_start: Option<Instant>,
    /// Speed multiplier (0.5 to 4.0) - shared for runtime updates
    pub speed: Arc<RwLock<f32>>,
    /// Buffer for graph events (clicks, etc.)
    pub events_buffer: Rc<RefCell<Vec<Event>>>,
    /// Clicked node for info modal display
    pub clicked_node: Option<petgraph::graph::NodeIndex>,
    /// Node info modal open state
    pub node_info_modal_open: bool,
    /// Map from graph NodeIndex to config_model.hosts index
    pub node_to_host: HashMap<petgraph::graph::NodeIndex, usize>,
    /// Frames to wait before auto-starting.
    /// Using a countdown instead of a boolean allows to render the UI before starting the visualization.
    /// This avoids lag when clicking on the Visualization tab.
    /// Note: 10 frames is an arbitrary value that gives enough time for the UI to render and images to load.
    pub auto_start_countdown: Option<u8>,
    /// Total number of flows processed since visualization started
    pub total_flows: u32,
    /// Flag to request a zoom/pan reset on the next frame
    pub reset_view_requested: bool,
    /// Countdown to delay fit-to-screen (waiting for layout to settle, e.g., after panel toggle or on initial load)
    pub delayed_fit_countdown: Option<u8>,
    /// Previous screen size (to reset view on window resize)
    pub last_screen_size: Option<egui::Vec2>,
    /// Whether the user has manually started the visualization at least once.
    /// Auto-restart on config change is only enabled after this.
    pub user_has_started: bool,
    /// Edit buffer for the node info modal (cloned from config on open, applied on Save)
    pub modal_edit_buffer: Option<Host>,
    /// The rect of the graph panel (updated each frame, used for screenshot region)
    pub graph_rect: Option<egui::Rect>,
    /// Screenshot export state machine
    pub export_state: ExportState,
}

impl Default for VisualizationTabState {
    fn default() -> Self {
        // Start with an empty graph; the default config from ConfigurationFileState
        // will be detected by handle_config_changes() on the first frame.
        let graph = VisualizationGraph::new(petgraph::stable_graph::StableGraph::default());
        Self {
            graph,
            flow_receiver: None,
            active_links: HashMap::new(),
            visualization_running: false,
            config_content: None,
            streamer: None,
            layout_initialized: false,
            known_ips: HashSet::new(),
            ip_to_node: HashMap::new(),
            visualization_start: None,
            speed: Arc::new(RwLock::new(1.0)),
            events_buffer: Rc::new(RefCell::new(Vec::new())),
            clicked_node: None,
            node_info_modal_open: false,
            node_to_host: HashMap::new(),
            auto_start_countdown: None,
            total_flows: 0,
            user_has_started: false,
            reset_view_requested: false,
            delayed_fit_countdown: Some(2), // Delay initial fit for bottom panel to be laid out
            last_screen_size: None,
            modal_edit_buffer: None,
            graph_rect: None,
            export_state: ExportState::Idle,
        }
    }
}

impl VisualizationTabState {
    /// Update state from a configuration (preserves some state)
    /// Note: caller should stop visualization before calling this if running
    pub fn update_from_config(&mut self, config: &config::Configuration) {
        let (graph, known_ips, ip_to_node, node_to_host) = Self::build_graph_from_config(config);
        self.graph = graph;
        self.known_ips = known_ips;
        self.ip_to_node = ip_to_node;
        self.node_to_host = node_to_host;
        self.layout_initialized = false;
    }

    /// Build graph from configuration (shared logic)
    fn build_graph_from_config(
        config: &config::Configuration,
    ) -> (
        VisualizationGraph,
        HashSet<Ipv4Addr>,
        HashMap<Ipv4Addr, petgraph::graph::NodeIndex>,
        HashMap<petgraph::graph::NodeIndex, usize>,
    ) {
        let mut graph = VisualizationGraph::new(petgraph::stable_graph::StableGraph::default());
        let mut known_ips = HashSet::new();
        let mut ip_to_node: HashMap<Ipv4Addr, petgraph::graph::NodeIndex> = HashMap::new();
        let mut node_to_host: HashMap<petgraph::graph::NodeIndex, usize> = HashMap::new();

        // Add one node per host (with all its IPs)
        for (host_idx, host) in config.hosts.iter().enumerate() {
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
        self.known_ips.contains(&ip)
    }

    /// Reset all flow counts on nodes and edges
    fn reset_flow_counts(&mut self) {
        self.total_flows = 0;
        for idx in self.graph.g().node_indices().collect::<Vec<_>>() {
            if let Some(node) = self.graph.g_mut().node_weight_mut(idx) {
                let payload = node.payload_mut();
                payload.flow_count = 0;
                payload.max_flow_count = 0;
            }
        }
        for idx in self.graph.g().edge_indices().collect::<Vec<_>>() {
            if let Some(edge) = self.graph.g_mut().edge_weight_mut(idx) {
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
            self.known_ips.len()
        );
        for ip in &self.known_ips {
            log::debug!("  - {}", ip);
        }

        let (sender, receiver) = std::sync::mpsc::channel();

        let streamer = FlowStreamer::new(config_content, speed.clone(), sender)?;
        streamer.start();

        self.streamer = Some(streamer);
        self.flow_receiver = Some(receiver);
        self.visualization_running = true;
        self.visualization_start = Some(Instant::now());
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
        self.visualization_running = false;
        if let Some(streamer) = &self.streamer {
            streamer.stop();
        }
        self.streamer = None;
        self.flow_receiver = None;
        self.active_links.clear();
        self.visualization_start = None;
        log::info!("Flow visualization stopped");
    }
}
