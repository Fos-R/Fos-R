use super::visualization_shapes::{
    COLOR_DNS, COLOR_HTTP, COLOR_HTTPS, COLOR_INACTIVE, COLOR_OTHER, COLOR_SMTP, COLOR_SSH,
    ICON_TINT_DARK, ICON_TINT_LIGHT, NetworkEdgeShape, NetworkNodeShape,
};
use super::visualization_stream::{FlowEvent, FlowStreamer};
use super::visualization_utils::distribute_nodes_circle;
use crate::shared::config_model::Host;
use crate::shared::configuration_file::ConfigurationFileState;
use eframe::egui;
use egui_graphs::{
    FruchtermanReingoldState, FruchtermanReingoldWithCenterGravity,
    FruchtermanReingoldWithCenterGravityState, LayoutForceDirected, SettingsInteraction,
    events::{Event, PayloadNodeClick},
    set_layout_state,
};
use fosr_lib::{L7Proto, OS, config, config::HostType};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::Ipv4Addr;
use std::rc::Rc;
use std::sync::mpsc::Receiver;
use std::sync::{Arc, RwLock};
use std::time::Duration;
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

type VisualizationGraph = egui_graphs::Graph<
    NodeData,
    EdgeData,
    petgraph::Undirected,
    petgraph::stable_graph::DefaultIx,
    NetworkNodeShape,
    NetworkEdgeShape,
>;

/// Represents the state of the visualization tab.
pub struct VisualizationTabState {
    pub graph: VisualizationGraph,
    pub flow_receiver: Option<Receiver<FlowEvent>>,
    pub active_links: HashMap<(Ipv4Addr, Ipv4Addr), ActiveLink>,
    pub visualization_running: bool,
    pub config_content: Option<String>,
    streamer: Option<FlowStreamer>,
    pub layout_initialized: bool,
    /// Set of known IPs from the configuration (for filtering Internet flows)
    known_ips: HashSet<Ipv4Addr>,
    /// Map from IP to node index for quick lookup
    ip_to_node: HashMap<Ipv4Addr, petgraph::graph::NodeIndex>,
    /// Visualization start time (for timestamp-based flow display)
    visualization_start: Option<Instant>,
    /// Speed multiplier (0.5 to 4.0) - shared for runtime updates
    pub speed: Arc<RwLock<f32>>,
    /// Buffer for graph events (clicks, etc.)
    events_buffer: Rc<RefCell<Vec<Event>>>,
    /// Clicked node for info modal display
    pub clicked_node: Option<petgraph::graph::NodeIndex>,
    /// Node info modal open state
    pub node_info_modal_open: bool,
    /// Map from graph NodeIndex to config_model.hosts index
    node_to_host: HashMap<petgraph::graph::NodeIndex, usize>,
    /// Frames to wait before auto-starting.
    /// Using a countdown instead of a boolean allows to render the UI before starting the visualization.
    /// This avoids lag when clicking on the Visualization tab.
    /// Note: 10 frames is an arbitrary value that gives enough time for the UI to render and images to load.
    auto_start_countdown: Option<u8>,
    /// Total number of flows processed since visualization started
    total_flows: u32,
    /// Flag to request a zoom/pan reset on the next frame
    pub reset_view_requested: bool,
    /// Previous screen size (to reset view on window resize)
    last_screen_size: Option<egui::Vec2>,
    /// Whether the user has manually started the visualization at least once.
    /// Auto-restart on config change is only enabled after this.
    user_has_started: bool,
    /// Edit buffer for the node info modal (cloned from config on open, applied on Save)
    modal_edit_buffer: Option<Host>,
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
            last_screen_size: None,
            modal_edit_buffer: None,
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
    fn is_known_ip(&self, ip: Ipv4Addr) -> bool {
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

pub fn show_visualization_tab_content(
    ui: &mut egui::Ui,
    state: &mut VisualizationTabState,
    configuration_file_state: &mut ConfigurationFileState,
) {
    // Load config file contents if a file is selected but content not yet loaded
    crate::shared::configuration_file::load_config_file_contents(configuration_file_state);

    // Handle config changes
    handle_config_changes(state, configuration_file_state);

    // Auto-start visualization with delay (allows UI to render first)
    if let Some(countdown) = state.auto_start_countdown {
        if countdown > 0 {
            state.auto_start_countdown = Some(countdown - 1);
        } else if !state.visualization_running {
            let config = state.config_content.clone();
            let speed = state.speed.clone();
            if let Err(e) = state.start_visualization(config.as_deref(), speed, true) {
                log::error!("Failed to auto-start visualization: {}", e);
            }
            state.auto_start_countdown = None;
        }
    }

    // Process incoming flow events
    process_flow_events(state);

    // Update active links (remove expired ones)
    update_active_links(state);

    // Update graph edges based on active links
    update_graph_edges(state);

    // Render UI
    render_graph_view(ui, state);

    // Process node click events and render info modal
    process_graph_events(state, configuration_file_state);
    render_node_info_modal(ui.ctx(), state, configuration_file_state);
}

/// Handle configuration file changes
fn handle_config_changes(
    state: &mut VisualizationTabState,
    configuration_file_state: &ConfigurationFileState,
) {
    // Check if config was removed
    let was_config_removed =
        state.config_content.is_some() && configuration_file_state.config_file_content.is_none();

    if was_config_removed {
        // Stop visualization if running, then reset to default
        if state.visualization_running {
            state.stop_visualization();
        }
        state.config_content = None;
        *state = VisualizationTabState::default();
        state.reset_view_requested = true;
        return;
    }

    // Check if config content has changed
    let needs_update = match (
        &state.config_content,
        &configuration_file_state.config_file_content,
    ) {
        (Some(current), Some(new)) => current != new,
        (None, Some(_)) => true,
        _ => false,
    };

    if needs_update {
        if let Some(ref config_content) = configuration_file_state.config_file_content {
            // Stop visualization if running before updating config
            let was_running = state.visualization_running;
            if was_running {
                state.stop_visualization();
            }

            let config = config::import_config(config_content);
            state.update_from_config(&config);
            state.config_content = Some(config_content.clone());
            // Only auto-restart if the user has started the visualization at least once
            if state.user_has_started {
                state.auto_start_countdown = Some(10);
            }
            state.reset_view_requested = true;
        }
    }
}

/// Process incoming flow events from the streamer
fn process_flow_events(state: &mut VisualizationTabState) {
    let events: Vec<FlowEvent> = if let Some(ref receiver) = state.flow_receiver {
        receiver.try_iter().collect()
    } else {
        return;
    };

    let now = Instant::now();

    for event in events {
        // Determine if this flow should be displayed:
        // - Both IPs known: display
        // - One IP known, one unknown: display as host<->Internet
        // - Both IPs unknown: skip (Internet<->Internet)
        let src_known = state.is_known_ip(event.src_ip);
        let dst_known = state.is_known_ip(event.dst_ip);

        log::debug!(
            "Flow: {} -> {} | src_known={}, dst_known={}",
            event.src_ip,
            event.dst_ip,
            src_known,
            dst_known
        );

        if !src_known && !dst_known {
            // Both are Internet IPs - skip this flow
            log::debug!("  -> Skipping (Internet<->Internet)");
            continue;
        }

        // Increment total flows counter
        state.total_flows += 1;

        // Map IPs to display IPs (unknown -> INTERNET_IP)
        let display_src = if src_known { event.src_ip } else { INTERNET_IP };
        let display_dst = if dst_known { event.dst_ip } else { INTERNET_IP };

        log::debug!(
            "  -> Displayed as: {} -> {} ({:?})",
            display_src,
            display_dst,
            event.protocol
        );

        let key = (display_src, display_dst);
        let reverse_key = (display_dst, display_src);

        let direction = if state.active_links.contains_key(&reverse_key) {
            LinkDirection::Bidirectional
        } else {
            LinkDirection::Forward
        };

        state.active_links.insert(
            key,
            ActiveLink {
                protocol: event.protocol,
                start_time: now,
                direction,
            },
        );

        // Increment flow counters on nodes and edges
        if let (Some(&src_idx), Some(&dst_idx)) = (
            state.ip_to_node.get(&display_src),
            state.ip_to_node.get(&display_dst),
        ) {
            // Find the edge (undirected graph, so check both directions)
            let edge_idx = state
                .graph
                .g()
                .find_edge(src_idx, dst_idx)
                .or_else(|| state.graph.g().find_edge(dst_idx, src_idx));

            if let Some(edge_idx) = edge_idx {
                // Increment node flow counters
                if let Some(node) = state.graph.g_mut().node_weight_mut(src_idx) {
                    node.payload_mut().flow_count += 1;
                }
                if let Some(node) = state.graph.g_mut().node_weight_mut(dst_idx) {
                    node.payload_mut().flow_count += 1;
                }
                // Increment edge flow counter (for thickness)
                if let Some(edge) = state.graph.g_mut().edge_weight_mut(edge_idx) {
                    edge.payload_mut().flow_count += 1;
                }
            }
        }
    }

    // Update max_flow_count for all nodes (for proportional sizing)
    let max_node_flow = state
        .graph
        .g()
        .node_indices()
        .filter_map(|idx| state.graph.g().node_weight(idx))
        .map(|n| n.payload().flow_count)
        .max()
        .unwrap_or(0);

    for idx in state.graph.g().node_indices().collect::<Vec<_>>() {
        if let Some(node) = state.graph.g_mut().node_weight_mut(idx) {
            node.payload_mut().max_flow_count = max_node_flow;
        }
    }

    // Update max_flow_count for all edges (for proportional sizing)
    let max_edge_flow = state
        .graph
        .g()
        .edge_indices()
        .filter_map(|idx| state.graph.g().edge_weight(idx))
        .map(|e| e.payload().flow_count)
        .max()
        .unwrap_or(0);

    for idx in state.graph.g().edge_indices().collect::<Vec<_>>() {
        if let Some(edge) = state.graph.g_mut().edge_weight_mut(idx) {
            edge.payload_mut().max_flow_count = max_edge_flow;
        }
    }
}

/// Update active links (remove expired ones)
fn update_active_links(state: &mut VisualizationTabState) {
    let now = Instant::now();
    // Base display time is 0.5s, adjusted by speed (faster = shorter display)
    let base_timeout_ms = 500.0;
    let speed = *state.speed.read().unwrap();
    let timeout = Duration::from_millis((base_timeout_ms / speed) as u64);

    state
        .active_links
        .retain(|_, link| now.duration_since(link.start_time) < timeout);
}

/// Update graph edges based on active links
fn update_graph_edges(state: &mut VisualizationTabState) {
    let graph = &mut state.graph;

    // Collect edge info first to avoid borrow issues
    // Each node can have multiple IPs, so we collect all IP lists for matching
    let edges_data: Vec<(petgraph::graph::EdgeIndex, Vec<Ipv4Addr>, Vec<Ipv4Addr>)> = graph
        .g()
        .edge_indices()
        .map(|edge| {
            let (source, target) = graph.g().edge_endpoints(edge).unwrap();
            let src_ips = graph.g()[source].payload().ip_addrs.clone();
            let dst_ips = graph.g()[target].payload().ip_addrs.clone();
            (edge, src_ips, dst_ips)
        })
        .collect();

    for (edge, src_ips, dst_ips) in edges_data {
        // Check all IP combinations for an active link
        let mut new_state = EdgeState::Inactive;

        'outer: for src_ip in &src_ips {
            for dst_ip in &dst_ips {
                let forward_key = (*src_ip, *dst_ip);
                let reverse_key = (*dst_ip, *src_ip);

                if let Some(link) = state.active_links.get(&forward_key) {
                    new_state = EdgeState::Active {
                        protocol: link.protocol,
                        start_time: link.start_time,
                        direction: link.direction.clone(),
                    };
                    break 'outer;
                } else if let Some(link) = state.active_links.get(&reverse_key) {
                    new_state = EdgeState::Active {
                        protocol: link.protocol,
                        start_time: link.start_time,
                        // we are using the reverse key, so we need to reverse the direction
                        direction: match link.direction {
                            LinkDirection::Forward => LinkDirection::Backward,
                            LinkDirection::Backward => LinkDirection::Forward,
                            LinkDirection::Bidirectional => LinkDirection::Bidirectional,
                        },
                    };
                    break 'outer;
                }
            }
        }

        // Update edge state (flow_count is preserved)
        if let Some(edge_mut) = graph.g_mut().edge_weight_mut(edge) {
            edge_mut.payload_mut().state = new_state;
        }
    }
}

/// Process graph click events from the event buffer
fn process_graph_events(
    state: &mut VisualizationTabState,
    configuration_file_state: &ConfigurationFileState,
) {
    let events: Vec<Event> = state.events_buffer.borrow_mut().drain(..).collect();

    for event in events {
        if let Event::NodeClick(PayloadNodeClick { id }) = event {
            let node_idx = petgraph::graph::NodeIndex::new(id);
            state.clicked_node = Some(node_idx);
            state.node_info_modal_open = true;

            // Clone the host into the edit buffer
            let host_idx = state.node_to_host.get(&node_idx).copied();
            state.modal_edit_buffer = host_idx.and_then(|idx| {
                configuration_file_state
                    .config_model
                    .as_ref()
                    .and_then(|c| c.hosts.get(idx).cloned())
            });
        }
    }
}

/// Render the node information modal for the clicked node
fn render_node_info_modal(
    ctx: &egui::Context,
    state: &mut VisualizationTabState,
    config_file_state: &mut ConfigurationFileState,
) {
    if !state.node_info_modal_open {
        return;
    }

    let Some(node_idx) = state.clicked_node else {
        return;
    };

    let Some(node) = state.graph.g().node_weight(node_idx) else {
        state.node_info_modal_open = false;
        state.clicked_node = None;
        return;
    };

    let node_data = node.payload().clone();
    let host_idx = state.node_to_host.get(&node_idx).copied();
    let has_edit_buffer = state.modal_edit_buffer.is_some();

    let mut save_clicked = false;
    let modal = egui::Modal::new(egui::Id::new("node_info_modal")).show(ctx, |ui| {
        ui.set_width(250.0);
        if has_edit_buffer {
            ui.heading("Edit Node Information");
        } else {
            ui.heading("Node Information");
        }

        ui.separator();

        // Node type with icon
        ui.horizontal(|ui| {
            let (image, type_str) = match node_data.node_type {
                NodeType::Server => (egui::include_image!("../../assets/server.png"), "Server"),
                NodeType::User => (egui::include_image!("../../assets/computer.png"), "User"),
                NodeType::Internet => (
                    egui::include_image!("../../assets/internet.png"),
                    "Internet",
                ),
            };
            let tint = if ui.style().visuals.dark_mode {
                ICON_TINT_DARK
            } else {
                ICON_TINT_LIGHT
            };
            ui.add(
                egui::Image::new(image)
                    .fit_to_exact_size(egui::vec2(20.0, 20.0))
                    .tint(tint),
            );
            ui.label(egui::RichText::new(type_str).strong());
        });

        ui.add_space(4.0);

        // Editable fields if we have an edit buffer (config loaded and host found)
        if let Some(ref mut host) = state.modal_edit_buffer {
            // Hostname
            ui.horizontal(|ui| {
                ui.label("Hostname:");
                let mut buf = host.hostname.clone().unwrap_or_default();
                if ui
                    .add(egui::TextEdit::singleline(&mut buf).hint_text("hostname"))
                    .changed()
                {
                    host.hostname = if buf.trim().is_empty() {
                        None
                    } else {
                        Some(buf)
                    };
                }
            });

            // OS
            ui.horizontal(|ui| {
                ui.label("OS:");
                let selected = host.os.as_deref().unwrap_or("<none>");
                egui::ComboBox::from_id_salt("modal_os")
                    .selected_text(selected)
                    .show_ui(ui, |ui| {
                        if ui.selectable_label(host.os.is_none(), "<none>").clicked() {
                            host.os = None;
                        }
                        if ui
                            .selectable_label(host.os.as_deref() == Some("Linux"), "Linux")
                            .clicked()
                        {
                            host.os = Some("Linux".to_string());
                        }
                        if ui
                            .selectable_label(host.os.as_deref() == Some("Windows"), "Windows")
                            .clicked()
                        {
                            host.os = Some("Windows".to_string());
                        }
                    });
            });

            // IP addresses
            ui.label("IP Addresses:");
            for iface in &mut host.interfaces {
                ui.horizontal(|ui| {
                    ui.add_space(16.0);
                    ui.add(egui::TextEdit::singleline(&mut iface.ip_addr).hint_text("0.0.0.0"));
                });
            }
        } else {
            // Read-only fallback (no config loaded or Internet node)
            if let Some(ref hostname) = node_data.hostname {
                ui.horizontal(|ui| {
                    ui.label("Hostname:");
                    ui.label(egui::RichText::new(hostname).monospace());
                });
            }
            // Don't show OS or IP for Internet node
            if node_data.node_type != NodeType::Internet {
                ui.horizontal(|ui| {
                    ui.label("OS:");
                    ui.label(egui::RichText::new(format!("{:?}", node_data.os)).monospace());
                });
                ui.label("IP Addresses:");
                for ip in &node_data.ip_addrs {
                    ui.horizontal(|ui| {
                        ui.add_space(16.0);
                        ui.label(egui::RichText::new(ip.to_string()).monospace());
                    });
                }
            }
        }

        ui.add_space(8.0);

        if has_edit_buffer {
            ui.horizontal(|ui| {
                if ui
                    .button(egui_material_icons::icons::ICON_CLOSE)
                    .on_hover_text("Cancel")
                    .clicked()
                {
                    ui.close();
                }
                if ui
                    .button(egui_material_icons::icons::ICON_SAVE)
                    .on_hover_text("Save")
                    .clicked()
                {
                    save_clicked = true;
                    ui.close();
                }
            });
        } else {
            if ui
                .button(egui_material_icons::icons::ICON_CLOSE)
                .on_hover_text("Close")
                .clicked()
            {
                ui.close();
            }
        }
    });

    // Apply changes to config model on Save
    if save_clicked {
        if let (Some(idx), Some(buffer)) = (host_idx, state.modal_edit_buffer.take()) {
            if let Some(host) = config_file_state
                .config_model
                .as_mut()
                .and_then(|c| c.hosts.get_mut(idx))
            {
                *host = buffer;
            }
            // Sync config model back to YAML so other tabs and handle_config_changes pick it up
            if let Some(model) = &config_file_state.config_model {
                if let Ok(yaml) = serde_yaml::to_string(model) {
                    config_file_state.config_file_content = Some(yaml);
                }
            }
        }
    }

    // Close on Escape or click outside (discard changes)
    if modal.should_close() {
        state.node_info_modal_open = false;
        state.clicked_node = None;
        state.modal_edit_buffer = None;
    }
}

/// Helper to render a single legend item inline (for edges)
fn legend_item_inline(ui: &mut egui::Ui, label: &str, color: egui::Color32) {
    ui.horizontal(|ui| {
        let rect = ui.allocate_space(egui::vec2(12.0, 12.0)).1;
        let painter = ui.painter();
        painter.circle_filled(rect.center(), 6.0, color);
        ui.add_space(-2.0);
        ui.label(label);
    });
}

/// Helper to render a legend item with an image (for nodes)
fn legend_item_with_image(ui: &mut egui::Ui, label: &str, image: egui::ImageSource) {
    ui.horizontal(|ui| {
        let tint = if ui.style().visuals.dark_mode {
            ICON_TINT_DARK
        } else {
            ICON_TINT_LIGHT
        };
        ui.add(
            egui::Image::new(image)
                .fit_to_exact_size(egui::vec2(20.0, 20.0))
                .tint(tint),
        );
        ui.add_space(-2.0);
        ui.label(label);
    });
}

/// Render the graph view
fn render_graph_view(ui: &mut egui::Ui, state: &mut VisualizationTabState) {
    egui::CentralPanel::default().show(ui.ctx(), |ui| {
        // Enable node clicking and dragging
        let interactions = SettingsInteraction::new()
            .with_node_clicking_enabled(true)
            .with_dragging_enabled(true);

        // Reset view on window resize
        let screen_size = ui.ctx().content_rect().size();
        match state.last_screen_size {
            Some(last) if last != screen_size => {
                state.last_screen_size = Some(screen_size);
                state.reset_view_requested = true;
            }
            None => state.last_screen_size = Some(screen_size),
            _ => {}
        }

        // When reset is requested, enable fit-to-screen for one frame
        // so egui_graphs recalculates the proper zoom/pan to center the graph
        let fit_to_screen = state.reset_view_requested;
        if state.reset_view_requested {
            state.reset_view_requested = false;
        }

        let mut graph_view = egui_graphs::GraphView::<
            NodeData,
            EdgeData,
            petgraph::Undirected,
            petgraph::stable_graph::DefaultIx,
            NetworkNodeShape,
            NetworkEdgeShape,
            FruchtermanReingoldWithCenterGravityState,
            LayoutForceDirected<FruchtermanReingoldWithCenterGravity>,
        >::new(&mut state.graph)
            .with_interactions(&interactions)
            .with_event_sink(&state.events_buffer)
            .with_styles(&egui_graphs::SettingsStyle::new().with_labels_always(true))
            .with_navigations(&egui_graphs::SettingsNavigation::new()
                .with_fit_to_screen_enabled(fit_to_screen)
                .with_zoom_and_pan_enabled(true)
            );

        // Disable force-directed layout to preserve circle layout
        // TODO: handle this properly instead of just deactivating the auto-layout
        if !state.layout_initialized {
            let layout_state = FruchtermanReingoldWithCenterGravityState {
                base: FruchtermanReingoldState {
                    is_running: false,
                    ..Default::default()
                },
                extras: Default::default(),
            };
            set_layout_state(ui, layout_state, None);
            state.layout_initialized = true;
        }

        ui.add(&mut graph_view);

        // Overlay control buttons in the top-left corner of the graph
        let panel_rect = ui.min_rect();
        egui::Area::new(egui::Id::new("viz_overlay_buttons"))
            .fixed_pos(panel_rect.left_top() + egui::vec2(4.0, 4.0))
            .order(egui::Order::Foreground)
            .show(ui.ctx(), |ui| {
                egui::Frame::popup(ui.style()).shadow(egui::epaint::Shadow::NONE).show(ui, |ui| {
                    ui.horizontal(|ui| {
                        if !state.visualization_running {
                            // Play / Continue: resume without resetting flow counts
                            let play_tooltip = if state.user_has_started { "Continue" } else { "Start" };
                            if ui.button(egui_material_icons::icons::ICON_PLAY_ARROW).on_hover_text(play_tooltip).clicked() {
                                state.user_has_started = true;
                                // Pass the user config if loaded, otherwise None (uses default BN model)
                                let config = state.config_content.clone();
                                let speed = state.speed.clone();
                                if let Err(e) = state.start_visualization(config.as_deref(), speed, false) {
                                    log::error!("Failed to start flow streamer: {}", e);
                                }
                            }
                            // Restart: reset all flow counts and start fresh
                            // Only visible after the user has started at least once
                            if state.user_has_started {
                                if ui.button(egui_material_icons::icons::ICON_RESTART_ALT).on_hover_text("Restart").clicked() {
                                    let config = state.config_content.clone();
                                    let speed = state.speed.clone();
                                    if let Err(e) = state.start_visualization(config.as_deref(), speed, true) {
                                        log::error!("Failed to start flow streamer: {}", e);
                                    }
                                }
                            }
                        } else {
                            if ui.button(egui_material_icons::icons::ICON_STOP).on_hover_text("Stop").clicked() {
                                state.stop_visualization();
                            }
                        }
                        if ui.button(egui_material_icons::icons::ICON_FIT_SCREEN).on_hover_text("Fit to screen").clicked() {
                            state.reset_view_requested = true;
                        }

                        ui.separator();

                        // Playback speed: −/+ buttons with discrete steps
                        let speed_steps: &[f32] = &[0.25, 0.5, 0.75, 1.0, 1.5, 2.0, 3.0, 4.0];
                        // Speed is an Arc, we cannot use it directly with the buttons,
                        // we need to read and write its value manually.
                        let mut speed_value = *state.speed.read().unwrap();
                        let current_idx = speed_steps.iter().position(|&s| (s - speed_value).abs() < 0.01);

                        if ui.button(egui_material_icons::icons::ICON_REMOVE)
                            .on_hover_text("Slow down")
                            .clicked()
                        {
                            if let Some(idx) = current_idx {
                                if idx > 0 {
                                    speed_value = speed_steps[idx - 1];
                                    *state.speed.write().unwrap() = speed_value;
                                }
                            }
                        }
                        ui.label(format!("{:.1}x", speed_value))
                            .on_hover_text("Playback speed — controls how fast network flows are simulated");
                        if ui.button(egui_material_icons::icons::ICON_ADD)
                            .on_hover_text("Speed up")
                            .clicked()
                        {
                            if let Some(idx) = current_idx {
                                if idx < speed_steps.len() - 1 {
                                    speed_value = speed_steps[idx + 1];
                                    *state.speed.write().unwrap() = speed_value;
                                }
                            }
                        }
                    });

                });
            });

        // Overlay stats (bottom-left of graph)
        egui::Area::new(egui::Id::new("viz_overlay_stats"))
            .fixed_pos(panel_rect.left_bottom() + egui::vec2(4.0, 0.0))
            .pivot(egui::Align2::LEFT_BOTTOM)
            .order(egui::Order::Foreground)
            .show(ui.ctx(), |ui| {
                egui::Frame::popup(ui.style()).shadow(egui::epaint::Shadow::NONE).show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(format!("Active: {}", state.active_links.len()))
                            .on_hover_text("Number of network links currently transmitting data.");
                        ui.separator();
                        ui.label(format!("Total flows: {}", state.total_flows))
                            .on_hover_text("Cumulative number of flows generated since the simulation started.");
                    });
                });
            });

        // Overlay legend: node types (top-right of graph)
        egui::Area::new(egui::Id::new("viz_overlay_node_legend"))
            .pivot(egui::Align2::RIGHT_TOP)
            .fixed_pos(panel_rect.right_top() + egui::vec2(-4.0, 4.0))
            .order(egui::Order::Foreground)
            .show(ui.ctx(), |ui| {
                egui::Frame::popup(ui.style()).shadow(egui::epaint::Shadow::NONE).show(ui, |ui| {
                    legend_item_with_image(ui, "Server", egui::include_image!("../../assets/server.png"));
                    legend_item_with_image(ui, "User", egui::include_image!("../../assets/computer.png"));
                    legend_item_with_image(ui, "Internet", egui::include_image!("../../assets/internet.png"));
                }).response.on_hover_text("Node types. Size reflects relative traffic activity.");
            });

        // Overlay legend: edge states (bottom-right of graph)
        egui::Area::new(egui::Id::new("viz_overlay_edge_legend"))
            .pivot(egui::Align2::RIGHT_BOTTOM)
            .fixed_pos(panel_rect.right_bottom() + egui::vec2(-4.0, -4.0))
            .order(egui::Order::Foreground)
            .show(ui.ctx(), |ui| {
                egui::Frame::popup(ui.style()).shadow(egui::epaint::Shadow::NONE).show(ui, |ui| {
                    legend_item_inline(ui, "Inactive", COLOR_INACTIVE);
                    legend_item_inline(ui, "HTTP", COLOR_HTTP);
                    legend_item_inline(ui, "HTTPS", COLOR_HTTPS);
                    legend_item_inline(ui, "SSH", COLOR_SSH);
                    legend_item_inline(ui, "DNS", COLOR_DNS);
                    legend_item_inline(ui, "SMTP", COLOR_SMTP);
                    legend_item_inline(ui, "Other", COLOR_OTHER);
                }).response.on_hover_text("Link protocols. Color shows protocol, thickness reflects relative traffic volume.");
            });
    });
}
