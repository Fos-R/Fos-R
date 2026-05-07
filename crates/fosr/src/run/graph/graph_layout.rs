//! Graph layout: radial sector-based distribution for subnet-clustered display,
//! and uniform circle layout for flat mode.
//!
//! Clustered mode: each subnet gets an angular sector proportional to its node count.
//! Host nodes are distributed on an inner arc within their sector.
//!
//! Flat mode: all nodes are evenly distributed on a single circle.

use crate::shared::constants::ui::{
    CLUSTER_GAP_RAD,
    GRAPH_LAYOUT_CLUSTER_RADIUS_MULTIPLIER, GRAPH_LAYOUT_CLUSTER_RADIUS_BASE,
    GRAPH_LAYOUT_FLAT_RADIUS_MULTIPLIER, GRAPH_LAYOUT_FLAT_RADIUS_BASE,
};
use super::state::VisualizationGraph;
use eframe::egui;
use std::collections::HashMap;
use petgraph::graph::NodeIndex;

/// Distribute all nodes evenly on a single circle (flat layout).
pub fn arrange_nodes_in_circle(
    graph: &mut VisualizationGraph,
) {
    let node_indices: Vec<NodeIndex> = graph.g().node_indices().collect();
    let n = node_indices.len();
    if n == 0 {
        return;
    }

    let node_count = n.max(1) as f32;
    let radius = node_count.sqrt() * GRAPH_LAYOUT_FLAT_RADIUS_MULTIPLIER + GRAPH_LAYOUT_FLAT_RADIUS_BASE;

    for (i, &idx) in node_indices.iter().enumerate() {
        let angle = (i as f32 / node_count) * std::f32::consts::TAU;
        if let Some(node) = graph.g_mut().node_weight_mut(idx) {
            node.set_location(egui::pos2(radius * angle.cos(), radius * angle.sin()));
        }
    }
}

/// Distribute nodes in a radial sector layout.
///
/// - Each subnet's sector span is proportional to its node count,
///   so a single-node cluster (like Internet) takes less space than a 5-host subnet.
/// - Host nodes are placed on an inner arc, evenly spaced within their sector.
pub fn arrange_nodes_in_clusters(
    graph: &mut VisualizationGraph,
    hosts_by_subnet: &HashMap<String, Vec<NodeIndex>>,
) {
    let subnet_count = hosts_by_subnet.len().max(1) as f32;
    let radius = subnet_count.sqrt() * GRAPH_LAYOUT_CLUSTER_RADIUS_MULTIPLIER + GRAPH_LAYOUT_CLUSTER_RADIUS_BASE;

    // Stable ordering: sort subnets alphabetically by name
    let subnet_order: Vec<String> = {
        let mut names: Vec<String> = hosts_by_subnet.keys().cloned().collect();
        names.sort();
        names
    };

    // Compute total nodes for proportional sector allocation
    let total_nodes: usize = subnet_order.iter()
        .filter_map(|name| hosts_by_subnet.get(name))
        .map(|hosts| hosts.len())
        .sum();
    let total_nodes = total_nodes.max(1) as f32;

    // Reserve a fraction of the circle for inter-cluster gaps
    let num_clusters = subnet_order.iter()
        .filter(|name| hosts_by_subnet.get(*name).map_or(false, |h| !h.is_empty()))
        .count()
        .max(1);
    let gap_per_cluster = CLUSTER_GAP_RAD;
    let total_gap = num_clusters as f32 * gap_per_cluster;
    let usable_span = (std::f32::consts::TAU - total_gap).max(0.0);

    // Position hosts on arc within their sector
    let mut sector_start = 0.0;
    for name in &subnet_order {
        let Some(hosts) = hosts_by_subnet.get(name) else { continue };
        let host_count = hosts.len();
        if host_count == 0 {
            continue;
        }

        // Sector span proportional to node count, within usable space
        let sector_span = (host_count as f32 / total_nodes) * usable_span;

        for (j, &host_idx) in hosts.iter().enumerate() {
            let t = (j as f32 + 1.0) / (host_count as f32 + 1.0);
            let angle = sector_start + t * sector_span;

            if let Some(node) = graph.g_mut().node_weight_mut(host_idx) {
                node.set_location(egui::pos2(
                    radius * angle.cos(),
                    radius * angle.sin(),
                ));
            }
        }

        sector_start += sector_span + gap_per_cluster;
    }
}
