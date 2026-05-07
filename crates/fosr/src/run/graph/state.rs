//! Visualization state: graph data, active links, flow processing, and export.

use super::shapes::{NetworkEdgeShape, NetworkNodeShape};
use super::stream::{FlowEvent, FlowStreamer};
use super::graph_layout::{arrange_nodes_in_circle, arrange_nodes_in_clusters};
use crate::shared::constants::ui::{DELAY_FRAMES_QUICK, ZONE_PAD_BASE, ZONE_PAD_LABEL, ZONE_PAD_TOP_INSET};
use fosr_lib::network::HostYaml;
use eframe::egui;
use egui_graphs::events::Event;
use fosr_lib::{L7Proto, OS, network, network::HostType, network::INTERNET_NETWORK_NAME};
use strum::EnumIter;
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
pub const INTERNET_NODE_IP: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 1);

/// Sentinel `net_idx` in `node_to_host` indicating the host lives in
/// `ConfigurationYaml.internet` rather than `ConfigurationYaml.networks[i]`.
pub const INTERNET_HOST_SENTINEL: usize = usize::MAX;

/// Synthetic cluster key for the fallback Internet node when no Internet subnet exists.
const FALLBACK_INTERNET_CLUSTER: &str = "__internet__";

/// How subnet zones are displayed in the graph.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, EnumIter)]
pub enum SubnetDisplayMode {
    /// All nodes placed on a single circle, no zone rectangles.
    Flat,
    /// Uniform color zone rectangles for all subnets.
    #[default]
    Subnet,
    /// Each subnet gets a distinct color (golden-ratio hue distribution).
    ColoredSubnets,
}

impl SubnetDisplayMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::Flat => "Flat",
            Self::Subnet => "Subnet",
            Self::ColoredSubnets => "Colored subnets",
        }
    }

    pub fn tooltip(self) -> &'static str {
        match self {
            Self::Flat => "No zones - nodes grouped without borders.",
            Self::Subnet => "Uniform zone color across all subnets.",
            Self::ColoredSubnets => "Each subnet gets a distinct color.",
        }
    }
}

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

/// Subnet zone rendering metadata, stored on the zone's designated drawer node.
#[derive(Clone, Debug)]
pub struct ZoneDisplay {
    /// Whether this node is designated to draw the subnet zone background.
    pub draws_zone: bool,
    /// Center of the zone bounding rectangle (canvas coordinates).
    pub center: egui::Pos2,
    /// Half-size of the zone bounding rectangle (canvas coordinates).
    pub half_size: egui::Vec2,
    /// Label of the zone (subnet name + CIDR).
    pub label: Option<String>,
    /// Color index for dynamic HSL generation.
    pub color_idx: usize,
    /// Current subnet display mode.
    pub subnet_mode: SubnetDisplayMode,
}

impl Default for ZoneDisplay {
    fn default() -> Self {
        Self {
            draws_zone: false,
            center: egui::Pos2::ZERO,
            half_size: egui::Vec2::ZERO,
            label: None,
            color_idx: 0,
            subnet_mode: SubnetDisplayMode::default(),
        }
    }
}

/// Node data: host information
#[derive(Clone, Debug)]
pub struct NetworkNode {
    pub ip_addrs: Vec<Ipv4Addr>,
    pub hostname: Option<String>,
    pub node_type: NodeType,
    #[allow(dead_code)] // Kept for possible future use (e.g., node styling by OS)
    pub os: OS,
    /// Number of flows this node has been involved in (as sender or receiver).
    /// Used for dynamic node sizing - more active nodes appear larger.
    pub flow_count: u32,
    /// Maximum flow count among all nodes (for proportional sizing).
    /// When the linear formula would exceed RADIUS_MAX, we switch to proportional mode.
    pub max_flow_count: u32,
    /// Subnet zone rendering metadata (populated on the zone's first node).
    pub zone: ZoneDisplay,
}

impl Default for NetworkNode {
    fn default() -> Self {
        Self {
            ip_addrs: Vec::new(),
            hostname: None,
            node_type: NodeType::User,
            os: OS::default(),
            flow_count: 0,
            max_flow_count: 0,
            zone: ZoneDisplay::default(),
        }
    }
}

impl NetworkNode {
    /// Create an Internet node
    pub fn internet() -> Self {
        Self {
            ip_addrs: vec![INTERNET_NODE_IP],
            hostname: Some(INTERNET_NETWORK_NAME.to_string()),
            node_type: NodeType::Internet,
            ..Default::default()
        }
    }
}

// Display the hostname plus all IP addresses
impl fmt::Display for NetworkNode {
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
pub struct NetworkEdge {
    /// Current visual state (active with protocol or inactive)
    pub state: EdgeState,
    /// Cumulative flow count - persists even when inactive, used for edge thickness
    pub flow_count: u32,
    /// Maximum flow count among all edges (for proportional sizing)
    pub max_flow_count: u32,
}

impl Default for NetworkEdge {
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
        #[allow(dead_code)] // Kept for possible future animation effects
        start_time: Instant,
        direction: LinkDirection,
    },
}

impl fmt::Display for NetworkEdge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.state {
            EdgeState::Inactive => write!(f, ""),
            EdgeState::Active { protocol, .. } => write!(f, "{:?}", protocol),
        }
    }
}

/// Direction of traffic flow on an edge.
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
    NetworkNode,
    NetworkEdge,
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

/// Subnet zone metadata for background rectangle rendering.
#[derive(Clone, Debug)]
pub struct SubnetZone {
    pub name: String,
    pub subnet: Ipv4Addr,
    pub mask: u8,
    pub host_indices: Vec<NodeIndex>,
}

/// Network structure with graph, IP/Node lookups, and construction methods.
///
/// Use [`NetworkData::from_config`] to build from a configuration.
pub struct NetworkData {
    pub graph: VisualizationGraph,
    pub known_ips: HashSet<Ipv4Addr>,
    pub ip_to_node: HashMap<Ipv4Addr, NodeIndex>,
    pub node_to_host: HashMap<NodeIndex, (usize, usize)>,
    pub subnet_zones: Vec<SubnetZone>,
}

impl Default for NetworkData {
    fn default() -> Self {
        Self {
            graph: VisualizationGraph::new(petgraph::stable_graph::StableGraph::default()),
            known_ips: HashSet::new(),
            ip_to_node: HashMap::new(),
            node_to_host: HashMap::new(),
            subnet_zones: Vec::new(),
        }
    }
}

impl NetworkData {
    /// Iterate over all node payloads mutably.
    fn for_each_node_mut(&mut self, mut f: impl FnMut(&mut NetworkNode)) {
        let indices: Vec<NodeIndex> = self.graph.g().node_indices().collect();
        for idx in indices {
            if let Some(node) = self.graph.g_mut().node_weight_mut(idx) {
                f(node.payload_mut());
            }
        }
    }
    /// Build network data from the configuration.
    ///
    /// Creates nodes for each host (including Internet subnet hosts),
    /// adds a synthetic Internet node for fallback communications,
    /// lays them out according to `mode`, and connects edges.
    pub fn from_config(config: &network::Configuration, mode: SubnetDisplayMode) -> Self {
        let mut data = Self::default();
        let has_internet_hosts = data.add_host_nodes(config);
        data.add_internet_node(has_internet_hosts);
        data.distribute_layout(mode);
        data.add_edges(config);
        data
    }

    /// Add one node per host (with all its IPs), grouped by network.
    ///
    /// Returns `true` if the Internet network had configured hosts.
    ///
    /// Hosts are identified by a `(net_idx, host_idx)` tuple stored in `node_to_host`,
    /// so the node modal can look up the corresponding `HostYaml` later.
    /// Internet hosts use [`INTERNET_HOST_SENTINEL`] as `net_idx` so the modal knows
    /// to look in `ConfigurationYaml.internet` instead of `networks`.
    fn add_host_nodes(&mut self, config: &network::Configuration) -> bool {
        let mut has_internet_hosts = false;

        for (net_idx, network) in config.networks.iter().enumerate() {
            if network.name == INTERNET_NETWORK_NAME {
                if network.hosts.is_empty() {
                    continue;
                }
                has_internet_hosts = true;
            }

            let mut zone = SubnetZone {
                name: network.name.clone(),
                subnet: network.subnet,
                mask: network.mask,
                host_indices: Vec::new(),
            };

            for (host_idx, host) in network.hosts.iter().enumerate() {
                // Map all IPs of this host to the same node
                let all_ips: Vec<Ipv4Addr> = host.interfaces.iter().map(|i| i.ip_addr).collect();

                let node_data = NetworkNode {
                    ip_addrs: all_ips.clone(),
                    hostname: host.hostname.clone(),
                    node_type: host.host_type.into(),
                    os: host.os,
                    ..Default::default()
                };

                // Nodes are initially inserted at position (0, 0). They are distributed in the available zone afterward.
                let idx = self.graph.add_node_with_location(node_data, egui::pos2(0.0, 0.0));

                // Use sentinel for Internet hosts so the modal looks in model.internet
                let host_key = if network.name == INTERNET_NETWORK_NAME {
                    (INTERNET_HOST_SENTINEL, host_idx)
                } else {
                    (net_idx, host_idx)
                };
                self.node_to_host.insert(idx, host_key);
                zone.host_indices.push(idx);

                for ip in &all_ips {
                    self.known_ips.insert(*ip);
                    self.ip_to_node.insert(*ip, idx);
                }
            }

            self.subnet_zones.push(zone);
        }

        has_internet_hosts
    }

    /// Compute the padded bounding box for a set of nodes.
    ///
    /// Returns `(center, half_size)` in canvas coordinates, or `None` if the
    /// node list is empty or no positions could be read.
    fn compute_zone_bounds(&self, host_indices: &[NodeIndex]) -> Option<(egui::Pos2, egui::Vec2)> {
        if host_indices.is_empty() {
            return None;
        }

        let mut min_x = f32::MAX;
        let mut min_y = f32::MAX;
        let mut max_x = f32::MIN;
        let mut max_y = f32::MIN;

        // Iterate over each node of the network to progressively enlarge the rectangle,
        // so that it includes all the nodes centers.
        for &idx in host_indices {
            if let Some(node) = self.graph.g().node_weight(idx) {
                let loc = node.location();
                min_x = min_x.min(loc.x);
                min_y = min_y.min(loc.y);
                max_x = max_x.max(loc.x);
                max_y = max_y.max(loc.y);
            }
        }

        // Add padding to include the node icons and labels in the rectangle.
        min_x -= ZONE_PAD_BASE + ZONE_PAD_LABEL;
        min_y -= ZONE_PAD_BASE - ZONE_PAD_TOP_INSET; // Smaller padding: there is no label above a node.
        max_x += ZONE_PAD_BASE + ZONE_PAD_LABEL;
        max_y += ZONE_PAD_BASE + ZONE_PAD_LABEL;

        Some((
            egui::pos2((min_x + max_x) / 2.0, (min_y + max_y) / 2.0),
            egui::vec2((max_x - min_x) / 2.0, (max_y - min_y) / 2.0),
        ))
    }

    /// Distribute nodes in the graph.
    ///
    /// In `Flat` mode, all nodes are placed evenly on a single circle.
    /// Otherwise, nodes are grouped by subnet in radial sectors.
    ///
    /// When an Internet subnet zone exists (i.e. Internet hosts are configured),
    /// the synthetic Internet node is placed inside that zone.
    /// Otherwise it gets its own standalone cluster.
    pub fn distribute_layout(&mut self, mode: SubnetDisplayMode) {
        let inet_zone_idx = self.subnet_zones.iter().position(|z| z.name == INTERNET_NETWORK_NAME);

        // Add synthetic Internet node into the Internet subnet zone when it exists
        if let Some(zone_idx) = inet_zone_idx
            && let Some(&inet_idx) = self.ip_to_node.get(&INTERNET_NODE_IP) {
                // Avoid duplicates on repeated calls (e.g. layout reset)
                if !self.subnet_zones[zone_idx].host_indices.contains(&inet_idx) {
                    self.subnet_zones[zone_idx].host_indices.push(inet_idx);
                }
            }

        if mode == SubnetDisplayMode::Flat {
            arrange_nodes_in_circle(&mut self.graph);
            return;
        }

        let mut hosts_by_subnet: HashMap<String, Vec<NodeIndex>> = HashMap::new();
        for zone in &self.subnet_zones {
            hosts_by_subnet.insert(zone.name.clone(), zone.host_indices.clone());
        }

        // When no Internet hosts, give the synthetic node its own cluster
        if inet_zone_idx.is_none()
            && let Some(&inet_idx) = self.ip_to_node.get(&INTERNET_NODE_IP) {
                hosts_by_subnet.insert(FALLBACK_INTERNET_CLUSTER.to_string(), vec![inet_idx]);
            }

        arrange_nodes_in_clusters(&mut self.graph, &hosts_by_subnet);

        self.assign_zone_metadata();
    }

    /// Compute zone bounding boxes and store metadata on each zone's first node.
    ///
    /// Called after layout to set `draws_zone`, bounding box, label, and color index
    /// on the designated node of each subnet zone.
    fn assign_zone_metadata(&mut self) {
        self.update_zone_bounds(true);
    }

    /// Update zone bounding boxes and optionally set full metadata on each zone's first node.
    ///
    /// When `full` is true (after layout), also sets `draws_zone`, label, and color index.
    /// When `full` is false (per-frame recomputation), only updates bounding boxes.
    fn update_zone_bounds(&mut self, full: bool) {
        // Sort zones by name for stable ordering and consistent color index
        let mut zone_order: Vec<usize> = (0..self.subnet_zones.len()).collect();
        zone_order.sort_by_key(|&i| &self.subnet_zones[i].name);

        for (order_idx, &zone_idx) in zone_order.iter().enumerate() {
            let zone = &self.subnet_zones[zone_idx];
            let hosts = &zone.host_indices;

            let (center, half_size) = match self.compute_zone_bounds(hosts) {
                Some(bounds) => bounds,
                None => continue,
            };

            // Reminder: the zone's data is stored in the first node of a subnet.
            if let Some(&first_idx) = hosts.first() {
                // Update the node's data relative to the zone.
                if let Some(node) = self.graph.g_mut().node_weight_mut(first_idx) {
                    let p = node.payload_mut();
                    p.zone.center = center;
                    p.zone.half_size = half_size;
                    if full {
                        p.zone.draws_zone = true;
                        // Do not display CIDR for the "Internet" zone.
                        p.zone.label = Some(if zone.name == INTERNET_NETWORK_NAME {
                            zone.name.clone()
                        } else {
                            format!("{}\n{}/{}", zone.name, zone.subnet, zone.mask)
                        });
                        p.zone.color_idx = order_idx;
                    }
                }
            }
        }
    }

    /// Add the synthetic Internet node for fallback communications.
    ///
    /// When `rename` is true (Internet hosts exist), the node is labeled
    /// "Rest of Internet" to distinguish it from configured Internet hosts.
    fn add_internet_node(&mut self, rename: bool) {
        let mut node = NetworkNode::internet();
        if rename {
            node.hostname = Some("Rest of Internet".to_string());
        }
        let internet_idx = self.graph.add_node_with_location(node, egui::pos2(0.0, 0.0));
        self.ip_to_node.insert(INTERNET_NODE_IP, internet_idx);
    }

    /// Recompute subnet zone bounding boxes from current node positions.
    ///
    /// Should be called each frame before rendering so that dragging a node
    /// causes its subnet rectangle to follow.
    pub fn recompute_zone_bounds(&mut self) {
        self.update_zone_bounds(false);
    }

    /// Propagate the current subnet display mode to all node payloads.
    pub fn set_subnet_mode(&mut self, mode: SubnetDisplayMode) {
        // Collect zone drawer nodes once
        let zone_drawers: HashSet<NodeIndex> = if mode != SubnetDisplayMode::Flat {
            self.subnet_zones.iter()
                .filter_map(|z| z.host_indices.first().copied())
                .collect()
        } else {
            HashSet::new()
        };

        self.for_each_node_mut(|p| {
            p.zone.subnet_mode = mode;
            p.zone.draws_zone = false;
        });

        // Re-enable zone drawing on designated nodes for non-flat modes
        for drawer_idx in &zone_drawers {
            if let Some(node) = self.graph.g_mut().node_weight_mut(*drawer_idx) {
                node.payload_mut().zone.draws_zone = true;
            }
        }
    }

    /// Add edges between users and servers per service, plus edges to Internet.
    fn add_edges(&mut self, config: &network::Configuration) {
        let internet_idx = self.ip_to_node.get(&INTERNET_NODE_IP).expect("Internet node must exist");

        for service in &config.services {
            let users = config.get_users_per_service(service);
            let servers = config.get_servers_per_service(service);

            for &user_ip in &users {
                if let Some(&user_idx) = self.ip_to_node.get(&user_ip) {
                    for &server_ip in &servers {
                        if let Some(&server_idx) = self.ip_to_node.get(&server_ip) {
                            self.graph.add_edge(user_idx, server_idx, NetworkEdge::default());
                        }
                    }
                }
            }
        }

        // Add edges from all user and server nodes to Internet
        let mut connected_to_internet: HashSet<NodeIndex> = HashSet::new();
        for &ip in config.users.iter().chain(config.servers.iter()) {
            if let Some(&idx) = self.ip_to_node.get(&ip)
                && connected_to_internet.insert(idx) {
                    self.graph.add_edge(idx, *internet_idx, NetworkEdge::default());
                }
        }
    }
}

/// Flow processing and streaming state
pub struct FlowVisualizationState {
    pub receiver: Option<Receiver<FlowEvent>>,
    pub active_links: HashMap<(Ipv4Addr, Ipv4Addr), ActiveLink>,
    pub streamer: Option<FlowStreamer>,
    pub running: bool,
    pub speed: Arc<RwLock<f32>>,
    pub total_flows: u32,
    pub visualization_start: Option<Instant>,
}

impl Default for FlowVisualizationState {
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
pub struct GraphViewState {
    pub layout_initialized: bool,
    pub fit_to_screen_requested: bool,
    /// When true, redistribute node positions and fit to screen.
    pub layout_reset_requested: bool,
    pub delayed_fit_countdown: Option<u8>,
    pub last_screen_size: Option<egui::Vec2>,
    pub graph_rect: Option<egui::Rect>,
}

impl Default for GraphViewState {
    fn default() -> Self {
        Self {
            layout_initialized: false,
            fit_to_screen_requested: false,
            layout_reset_requested: false,
            delayed_fit_countdown: Some(DELAY_FRAMES_QUICK), // Delay initial fit for bottom panel
            last_screen_size: None,
            graph_rect: None,
        }
    }
}

/// Node info modal state
pub struct NodeModalState {
    pub events_buffer: Rc<RefCell<Vec<Event>>>,
    pub clicked_node: Option<NodeIndex>,
    pub open: bool,
    pub edit_buffer: Option<HostYaml>,
}

impl Default for NodeModalState {
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
#[derive(Default)]
pub struct VisualizationState {
    /// Network structure and lookups
    pub network: NetworkData,
    /// Flow processing and streaming
    pub flow: FlowVisualizationState,
    /// Layout and rendering
    pub view: GraphViewState,
    /// Node info modal
    pub modal: NodeModalState,
    /// Screenshot export state machine
    pub screenshot_export: ScreenshotStateMachine,
    /// Config content tracking (for detecting changes)
    pub config_content: Option<String>,
    /// Auto-start countdown frames
    pub auto_start_countdown: Option<u8>,
    /// Whether user has manually started visualization
    pub user_has_started: bool,
    /// Current subnet display mode
    pub subnet_mode: SubnetDisplayMode,
}


impl VisualizationState {
    /// Update state from a configuration (preserves some state).
    /// Note: caller should stop visualization before calling this if running.
    pub fn update_from_config(&mut self, config: &network::Configuration) {
        let mode = self.subnet_mode;
        self.network = NetworkData::from_config(config, mode);
        self.network.set_subnet_mode(mode);
        self.view.layout_initialized = false;
    }

    /// Check if an IP is a known (configured) IP
    pub fn is_known_ip(&self, ip: Ipv4Addr) -> bool {
        self.network.known_ips.contains(&ip)
    }

    /// Reset all flow counts on nodes and edges
    fn reset_flow_counts(&mut self) {
        self.flow.total_flows = 0;
        self.network.for_each_node_mut(|p| {
            p.flow_count = 0;
            p.max_flow_count = 0;
        });
        for idx in self.network.graph.g().edge_indices().collect::<Vec<_>>() {
            if let Some(edge) = self.network.graph.g_mut().edge_weight_mut(idx) {
                let payload = edge.payload_mut();
                payload.flow_count = 0;
                payload.max_flow_count = 0;
            }
        }
    }

    /// Start visualization.
    ///
    /// If `config_content` is `None`, the FlowStreamer uses the default BN model (no config applied).
    /// Speed controls how fast flows are emitted (1.0 = real-time, 2.0 = 2x faster) - can be updated at runtime.
    /// If `reset` is `true`, flow counts are reset to zero before starting.
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
