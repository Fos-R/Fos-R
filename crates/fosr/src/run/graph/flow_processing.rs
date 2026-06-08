//! Flow event processing for network visualization.
//!
//! This module handles the processing of flow events from the streamer,
//! updating active links, and synchronizing graph edge states.

use super::state::{ActiveLink, EdgeState, INTERNET_NODE_IP, LinkDirection, VisualizationState};
use super::stream::FlowEvent;
use crate::shared::constants::ui::ACTIVE_LINK_BASE_TIMEOUT_MS;

/// Process incoming flow events from the streamer.
///
/// Reads all pending events from the flow receiver and updates:
/// - Active links (for visual edge highlighting)
/// - Node flow counters (for proportional node sizing)
/// - Edge flow counters (for edge thickness)
///
/// Flows between two unknown IPs (Internet<->Internet) are filtered out.
pub fn process_flow_events(state: &mut VisualizationState) {
    let events: Vec<FlowEvent> = if let Some(ref receiver) = state.flow.receiver {
        receiver.try_iter().collect()
    } else {
        return;
    };

    let now = web_time::Instant::now();

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
        state.flow.total_flows += 1;

        // Map unknown IPs to the Internet node for display
        let display_src = if src_known {
            event.src_ip
        } else {
            INTERNET_NODE_IP
        };
        let display_dst = if dst_known {
            event.dst_ip
        } else {
            INTERNET_NODE_IP
        };

        log::debug!(
            "  -> Displayed as: {} -> {} ({:?})",
            display_src,
            display_dst,
            event.protocol
        );

        let key = (display_src, display_dst);
        let reverse_key = (display_dst, display_src);

        let direction = if state.flow.active_links.contains_key(&reverse_key) {
            LinkDirection::Bidirectional
        } else {
            LinkDirection::Forward
        };

        state.flow.active_links.insert(
            key,
            ActiveLink {
                protocol: event.protocol,
                start_time: now,
                direction,
            },
        );

        // Increment flow counters on nodes and edges
        if let (Some(&src_idx), Some(&dst_idx)) = (
            state.network.ip_to_node.get(&display_src),
            state.network.ip_to_node.get(&display_dst),
        ) {
            // Find the edge (undirected graph, so check both directions)
            let edge_idx = state
                .network
                .graph
                .g()
                .find_edge(src_idx, dst_idx)
                .or_else(|| state.network.graph.g().find_edge(dst_idx, src_idx));

            if let Some(edge_idx) = edge_idx {
                // Increment node flow counters
                if let Some(node) = state.network.graph.g_mut().node_weight_mut(src_idx) {
                    node.payload_mut().flow_count += 1;
                }
                if let Some(node) = state.network.graph.g_mut().node_weight_mut(dst_idx) {
                    node.payload_mut().flow_count += 1;
                }
                // Increment edge flow counter (for thickness)
                if let Some(edge) = state.network.graph.g_mut().edge_weight_mut(edge_idx) {
                    edge.payload_mut().flow_count += 1;
                }
            }
        }
    }

    // Update max_flow_count for all nodes (for proportional sizing)
    let max_node_flow = state
        .network
        .graph
        .g()
        .node_indices()
        .filter_map(|idx| state.network.graph.g().node_weight(idx))
        .map(|n| n.payload().flow_count)
        .max()
        .unwrap_or(0);

    for idx in state.network.graph.g().node_indices().collect::<Vec<_>>() {
        if let Some(node) = state.network.graph.g_mut().node_weight_mut(idx) {
            node.payload_mut().max_flow_count = max_node_flow;
        }
    }

    // Update max_flow_count for all edges (for proportional sizing)
    let max_edge_flow = state
        .network
        .graph
        .g()
        .edge_indices()
        .filter_map(|idx| state.network.graph.g().edge_weight(idx))
        .map(|e| e.payload().flow_count)
        .max()
        .unwrap_or(0);

    for idx in state.network.graph.g().edge_indices().collect::<Vec<_>>() {
        if let Some(edge) = state.network.graph.g_mut().edge_weight_mut(idx) {
            edge.payload_mut().max_flow_count = max_edge_flow;
        }
    }
}

/// Update active links by removing expired ones.
///
/// Links expire after a timeout period adjusted by the current speed setting.
pub fn update_active_links(state: &mut VisualizationState) {
    let now = web_time::Instant::now();
    // Base display time is 0.5s, adjusted by speed (faster = shorter display)
    let base_timeout_ms = ACTIVE_LINK_BASE_TIMEOUT_MS;
    let speed = *state.flow.speed.read().unwrap();
    let timeout = std::time::Duration::from_millis((base_timeout_ms / speed) as u64);

    state
        .flow
        .active_links
        .retain(|_, link| now.duration_since(link.start_time) < timeout);
}

/// Update graph edge states based on active links.
///
/// For each edge, checks if any IP combination has an active link
/// and updates the edge's visual state accordingly.
pub fn update_graph_edges(state: &mut VisualizationState) {
    let graph = &mut state.network.graph;

    // Collect edge info first to avoid borrow issues
    // Each node can have multiple IPs, so we collect all IP lists for matching
    let edges_data: Vec<(
        petgraph::graph::EdgeIndex,
        Vec<std::net::Ipv4Addr>,
        Vec<std::net::Ipv4Addr>,
    )> = graph
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
        let new_state = find_active_link_state(&state.flow.active_links, &src_ips, &dst_ips);

        // Update edge state (flow_count is preserved)
        if let Some(edge_mut) = graph.g_mut().edge_weight_mut(edge) {
            edge_mut.payload_mut().state = new_state;
        }
    }
}

/// Find the active link state for an edge by checking all IP combinations.
///
/// Searches for an active link between any source IP and any destination IP,
/// handling both forward and reverse directions.
fn find_active_link_state(
    active_links: &std::collections::HashMap<(std::net::Ipv4Addr, std::net::Ipv4Addr), ActiveLink>,
    src_ips: &[std::net::Ipv4Addr],
    dst_ips: &[std::net::Ipv4Addr],
) -> EdgeState {
    for src_ip in src_ips {
        for dst_ip in dst_ips {
            let forward_key = (*src_ip, *dst_ip);
            let reverse_key = (*dst_ip, *src_ip);

            if let Some(link) = active_links.get(&forward_key) {
                return EdgeState::Active {
                    protocol: link.protocol,
                    start_time: link.start_time,
                    direction: link.direction.clone(),
                };
            } else if let Some(link) = active_links.get(&reverse_key) {
                // Reverse key: flip the direction
                return EdgeState::Active {
                    protocol: link.protocol,
                    start_time: link.start_time,
                    direction: match link.direction {
                        LinkDirection::Forward => LinkDirection::Backward,
                        LinkDirection::Backward => LinkDirection::Forward,
                        LinkDirection::Bidirectional => LinkDirection::Bidirectional,
                    },
                };
            }
        }
    }
    EdgeState::Inactive
}
