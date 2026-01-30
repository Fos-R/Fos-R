use super::visualization_shapes::{
    NetworkEdgeShape, NetworkNodeShape, COLOR_DNS, COLOR_HTTP, COLOR_HTTPS, COLOR_INACTIVE,
    COLOR_INTERNET, COLOR_SERVER, COLOR_SSH, COLOR_USER,
};
use super::visualization_stream::{FlowEvent, FlowStreamer};
use super::visualization_utils::distribute_nodes_circle;
use crate::shared::configuration_file::ConfigurationFileState;
use eframe::egui;
use egui_graphs::{
    FruchtermanReingoldState, FruchtermanReingoldWithCenterGravity,
    FruchtermanReingoldWithCenterGravityState, LayoutForceDirected, set_layout_state,
};
use fosr_lib::{config, config::HostType, L7Proto, OS};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::Ipv4Addr;
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
    pub ip_addr: Ipv4Addr,
    pub hostname: Option<String>,
    pub node_type: NodeType,
    #[allow(dead_code)] // Kept for possible future use (node styling by OS?)
    pub os: OS,
}

impl NodeData {
    /// Create an Internet node
    pub fn internet() -> Self {
        Self {
            ip_addr: INTERNET_IP,
            hostname: Some("Internet".to_string()),
            node_type: NodeType::Internet,
            os: OS::Linux, // Doesn't matter for Internet node
        }
    }
}

// Display the IP address, plus the hostname if available
impl fmt::Display for NodeData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref hostname) = self.hostname {
            if self.node_type == NodeType::Internet {
                write!(f, "{}", hostname)
            } else {
                write!(f, "{}\n{}", hostname, self.ip_addr)
            }
        } else {
            write!(f, "{}", self.ip_addr)
        }
    }
}

/// Edge data: communication state
#[derive(Clone, Debug, Default)]
pub enum EdgeData {
    #[default]
    Inactive,
    Active {
        protocol: L7Proto,
        #[allow(dead_code)] // Kept for possible future animation effects?
        start_time: Instant,
        #[allow(dead_code)] // Kept for directional arrows
        direction: LinkDirection,
    },
}

impl fmt::Display for EdgeData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EdgeData::Inactive => write!(f, ""),
            EdgeData::Active { protocol, .. } => write!(f, "{:?}", protocol),
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
}

impl Default for VisualizationTabState {
    fn default() -> Self {
        Self::create_demo_state()
    }
}

impl VisualizationTabState {
    /// Create a demo state with all IPs from the BN models (bn_additional_data.json)
    /// TODO: only a subset of them seems to appear in the generated data, prune the unused ones
    fn create_demo_state() -> Self {
        // All IPs from bn_additional_data.json (excluding 0.0.0.0)
        // Servers are x.x.x.2, Users are x.x.x.3+
        let demo_hosts: Vec<(Ipv4Addr, NodeType)> = vec![
            // 192.168.100.x
            (Ipv4Addr::new(192, 168, 100, 2), NodeType::Server),
            (Ipv4Addr::new(192, 168, 100, 3), NodeType::User),
            (Ipv4Addr::new(192, 168, 100, 4), NodeType::User),
            (Ipv4Addr::new(192, 168, 100, 5), NodeType::User),
            (Ipv4Addr::new(192, 168, 100, 6), NodeType::User),
            // 192.168.200.x
            (Ipv4Addr::new(192, 168, 200, 2), NodeType::Server),
            (Ipv4Addr::new(192, 168, 200, 3), NodeType::User),
            (Ipv4Addr::new(192, 168, 200, 4), NodeType::User),
            (Ipv4Addr::new(192, 168, 200, 5), NodeType::User),
            (Ipv4Addr::new(192, 168, 200, 8), NodeType::User),
            (Ipv4Addr::new(192, 168, 200, 9), NodeType::User),
            // 192.168.210.x
            (Ipv4Addr::new(192, 168, 210, 2), NodeType::Server),
            (Ipv4Addr::new(192, 168, 210, 3), NodeType::User),
            (Ipv4Addr::new(192, 168, 210, 4), NodeType::User),
            (Ipv4Addr::new(192, 168, 210, 5), NodeType::User),
            // 192.168.220.x
            (Ipv4Addr::new(192, 168, 220, 2), NodeType::Server),
            (Ipv4Addr::new(192, 168, 220, 3), NodeType::User),
            (Ipv4Addr::new(192, 168, 220, 4), NodeType::User),
            (Ipv4Addr::new(192, 168, 220, 5), NodeType::User),
            (Ipv4Addr::new(192, 168, 220, 6), NodeType::User),
            (Ipv4Addr::new(192, 168, 220, 7), NodeType::User),
            (Ipv4Addr::new(192, 168, 220, 8), NodeType::User),
            (Ipv4Addr::new(192, 168, 220, 9), NodeType::User),
            (Ipv4Addr::new(192, 168, 220, 10), NodeType::User),
            (Ipv4Addr::new(192, 168, 220, 11), NodeType::User),
            (Ipv4Addr::new(192, 168, 220, 12), NodeType::User),
            (Ipv4Addr::new(192, 168, 220, 13), NodeType::User),
            (Ipv4Addr::new(192, 168, 220, 14), NodeType::User),
            (Ipv4Addr::new(192, 168, 220, 15), NodeType::User),
            (Ipv4Addr::new(192, 168, 220, 16), NodeType::User),
        ];

        let mut graph = VisualizationGraph::new(petgraph::stable_graph::StableGraph::default());
        let mut known_ips = HashSet::new();
        let mut ip_to_node = HashMap::new();

        // Add demo nodes
        for (ip, node_type) in &demo_hosts {
            let node_data = NodeData {
                ip_addr: *ip,
                hostname: None, // No hostname, just show IP
                node_type: *node_type,
                os: OS::Linux, // Does not matter
            };
            // Nodes are initially placed at the center. They are manually distributed later.
            let idx = graph.add_node_with_location(node_data, egui::pos2(0.0, 0.0));
            known_ips.insert(*ip);
            ip_to_node.insert(*ip, idx);
        }

        // Distribute nodes before adding the Internet node, so that it stays in the center
        distribute_nodes_circle(&mut graph);

        // Add Internet node
        let internet_idx =
            graph.add_node_with_location(NodeData::internet(), egui::pos2(0.0, 0.0));
        ip_to_node.insert(INTERNET_IP, internet_idx);

        // Add edges between users and servers
        // TODO: make sure that all flows occur between a server and a user, never between 2 servers or 2 users or a server and the Internet
        let users: Vec<_> = demo_hosts
            .iter()
            .filter(|(_, t)| *t == NodeType::User)
            .collect();
        let servers: Vec<_> = demo_hosts
            .iter()
            .filter(|(_, t)| *t == NodeType::Server)
            .collect();

        for (user_ip, _) in &users {
            for (server_ip, _) in &servers {
                let user_idx = ip_to_node[user_ip];
                let server_idx = ip_to_node[server_ip];
                graph.add_edge(user_idx, server_idx, EdgeData::Inactive);
            }
            // Add edge to Internet for each user
            let user_idx = ip_to_node[user_ip];
            graph.add_edge(user_idx, internet_idx, EdgeData::Inactive);
        }

        // Add edges from servers to Internet
        for (server_ip, _) in &servers {
            let server_idx = ip_to_node[server_ip];
            graph.add_edge(server_idx, internet_idx, EdgeData::Inactive);
        }

        Self {
            graph,
            flow_receiver: None,
            active_links: HashMap::new(),
            visualization_running: false,
            config_content: None,
            streamer: None,
            layout_initialized: false,
            known_ips,
            ip_to_node,
            visualization_start: None,
            speed: Arc::new(RwLock::new(1.0)),
        }
    }

    /// Update state from a configuration (preserves some state)
    pub fn update_from_config(&mut self, config: &config::Configuration) {
        // Don't update while running
        // TODO: provide better handling if configuration changes during generation
        if self.visualization_running {
            return;
        }

        let (graph, known_ips, ip_to_node) = Self::build_graph_from_config(config);
        self.graph = graph;
        self.known_ips = known_ips;
        self.ip_to_node = ip_to_node;
        self.layout_initialized = false;
    }

    /// Build graph from configuration (shared logic)
    fn build_graph_from_config(
        config: &config::Configuration,
    ) -> (
        VisualizationGraph,
        HashSet<Ipv4Addr>,
        HashMap<Ipv4Addr, petgraph::graph::NodeIndex>,
    ) {
        let mut graph = VisualizationGraph::new(petgraph::stable_graph::StableGraph::default());
        let mut known_ips = HashSet::new();
        let mut ip_to_node: HashMap<Ipv4Addr, petgraph::graph::NodeIndex> = HashMap::new();

        // Add nodes for each host interface
        // TODO: it would be better to have one single node per host
        for host in &config.hosts {
            for interface in &host.interfaces {
                let node_data = NodeData {
                    ip_addr: interface.ip_addr,
                    hostname: host.hostname.clone(),
                    node_type: host.host_type.into(),
                    os: host.os,
                };
                let idx = graph.add_node_with_location(node_data, egui::pos2(0.0, 0.0));
                known_ips.insert(interface.ip_addr);
                ip_to_node.insert(interface.ip_addr, idx);
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
                        graph.add_edge(user_idx, server_idx, EdgeData::Inactive);
                    }
                }
                // Add edge to Internet for each user
                graph.add_edge(user_idx, internet_idx, EdgeData::Inactive);
            }
        }

        // Add edges from servers to Internet
        for &server_ip in &config.servers {
            if let Some(&server_idx) = ip_to_node.get(&server_ip) {
                graph.add_edge(server_idx, internet_idx, EdgeData::Inactive);
            }
        }

        (graph, known_ips, ip_to_node)
    }

    /// Check if an IP is a known (configured) IP
    fn is_known_ip(&self, ip: Ipv4Addr) -> bool {
        self.known_ips.contains(&ip)
    }

    /// Start visualization
    /// If config_content is None, the FlowStreamer uses the default BN model (no config applied)
    /// Speed controls how fast flows are emitted (1.0 = real-time, 2.0 = 2x faster) - can be updated at runtime via slider
    pub fn start_visualization(
        &mut self,
        config_content: Option<&str>,
        speed: Arc<RwLock<f32>>,
    ) -> Result<(), String> {
        log::debug!("Starting visualization with {} known IPs:", self.known_ips.len());
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
    configuration_file_state: &ConfigurationFileState,
) {
    // Handle config changes
    handle_config_changes(state, configuration_file_state);

    // Process incoming flow events
    process_flow_events(state);

    // Update active links (remove expired ones)
    update_active_links(state);

    // Update graph edges based on active links
    update_graph_edges(state);

    // Render UI
    render_control_panel(ui, state);
    render_graph_view(ui, state);
}

/// Handle configuration file changes
fn handle_config_changes(
    state: &mut VisualizationTabState,
    configuration_file_state: &ConfigurationFileState,
) {
    // Check if config was removed
    let was_config_removed =
        state.config_content.is_some() && configuration_file_state.config_file_content.is_none();

    if was_config_removed && !state.visualization_running {
        state.config_content = None;
        *state = VisualizationTabState::default();
        return;
    }

    // Check if config content has changed
    let needs_update = match (&state.config_content, &configuration_file_state.config_file_content)
    {
        (Some(current), Some(new)) => current != new,
        (None, Some(_)) => true,
        _ => false,
    };

    if needs_update && !state.visualization_running {
        if let Some(ref config_content) = configuration_file_state.config_file_content {
            state.active_links.clear();
            if let Some(streamer) = &state.streamer {
                streamer.stop();
            }
            state.streamer = None;
            state.flow_receiver = None;

            let config = config::import_config(config_content);
            state.update_from_config(&config);
            state.config_content = Some(config_content.clone());
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

        // Map IPs to display IPs (unknown -> INTERNET_IP)
        let display_src = if src_known {
            event.src_ip
        } else {
            INTERNET_IP
        };
        let display_dst = if dst_known {
            event.dst_ip
        } else {
            INTERNET_IP
        };

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
    let edges_data: Vec<(petgraph::graph::EdgeIndex, Ipv4Addr, Ipv4Addr)> = graph
        .g()
        .edge_indices()
        .map(|edge| {
            let (source, target) = graph.g().edge_endpoints(edge).unwrap();
            let src_ip = graph.g()[source].payload().ip_addr;
            let dst_ip = graph.g()[target].payload().ip_addr;
            (edge, src_ip, dst_ip)
        })
        .collect();

    for (edge, src_ip, dst_ip) in edges_data {
        let forward_key = (src_ip, dst_ip);
        let reverse_key = (dst_ip, src_ip);

        let new_edge_data = if let Some(link) = state.active_links.get(&forward_key) {
            EdgeData::Active {
                protocol: link.protocol,
                start_time: link.start_time,
                direction: link.direction.clone(),
            }
        } else if let Some(link) = state.active_links.get(&reverse_key) {
            EdgeData::Active {
                protocol: link.protocol,
                start_time: link.start_time,
                // we are using the reverse key, so we need to reverse the direction
                direction: match link.direction {
                    LinkDirection::Forward => LinkDirection::Backward,
                    LinkDirection::Backward => LinkDirection::Forward,
                    LinkDirection::Bidirectional => LinkDirection::Bidirectional,
                },
            }
        } else {
            EdgeData::Inactive
        };

        // Update the edge data
        if let Some(edge_mut) = graph.g_mut().edge_weight_mut(edge) {
            *edge_mut.payload_mut() = new_edge_data;
        }
    }
}

/// Render the control panel
fn render_control_panel(ui: &mut egui::Ui, state: &mut VisualizationTabState) {
    egui::TopBottomPanel::top("visualization_controls").show(ui.ctx(), |ui| {
        ui.vertical(|ui| {
            // Row 1: Button + label
            ui.horizontal(|ui| {
                if !state.visualization_running {
                    if ui.button("Start Visualization").clicked() {
                        // Clone config to avoid borrow issues
                        // Pass the user config if loaded, otherwise None (uses default BN model)
                        let config = state.config_content.clone();
                        let speed = state.speed.clone();
                        if let Err(e) = state.start_visualization(config.as_deref(), speed) {
                            log::error!("Failed to start flow streamer: {}", e);
                        }
                    }

                    if state.config_content.is_none() {
                        ui.label(
                            egui::RichText::new("(Demo mode - load a config for custom network)")
                                .color(egui::Color32::GRAY),
                        );
                    }
                } else {
                    if ui.button("Stop").clicked() {
                        state.stop_visualization();
                    }
                }
            });

            ui.separator();

            // Row 2: Speed slider + active links
            ui.horizontal(|ui| {
                ui.label("Speed:");
                // Speed is an Arc, we cannot use it directly with slider,
                // we need to read and write its value manually.
                let mut speed_value = *state.speed.read().unwrap();
                let response = ui.add(
                    egui::Slider::new(&mut speed_value, 0.5..=4.0)
                        .logarithmic(true)
                        .text("x"),
                );
                if response.changed() {
                    *state.speed.write().unwrap() = speed_value;
                }

                ui.separator();
                ui.label(format!("Active links: {}", state.active_links.len()));
            });

            ui.separator();

            // Row 3: Legend - Node types
            ui.horizontal(|ui| {
                ui.label("Node Types:");
                legend_item_inline(ui, "Server", COLOR_SERVER);
                legend_item_inline(ui, "User", COLOR_USER);
                legend_item_inline(ui, "Internet", COLOR_INTERNET);
            });

            // Row 4: Legend - Edge states
            ui.horizontal(|ui| {
                ui.label("Edge States:");
                legend_item_inline(ui, "Inactive", COLOR_INACTIVE);
                legend_item_inline(ui, "HTTP", COLOR_HTTP);
                legend_item_inline(ui, "HTTPS", COLOR_HTTPS);
                legend_item_inline(ui, "SSH", COLOR_SSH);
                legend_item_inline(ui, "DNS", COLOR_DNS);
            });
        });
    });
}

/// Helper to render a single legend item inline
fn legend_item_inline(ui: &mut egui::Ui, label: &str, color: egui::Color32) {
    // Allocate space first
    let rect = ui.allocate_space(egui::vec2(12.0, 12.0)).1;
    // Then get painter and draw
    let painter = ui.painter();
    painter.circle_filled(rect.center(), 6.0, color);
    ui.label(label);
}

/// Render the graph view
fn render_graph_view(ui: &mut egui::Ui, state: &mut VisualizationTabState) {
    egui::CentralPanel::default().show(ui.ctx(), |ui| {
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
            .with_styles(&egui_graphs::SettingsStyle::new().with_labels_always(true));

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
    });
}
