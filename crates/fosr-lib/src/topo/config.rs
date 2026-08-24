//! Configure/Structures

use serde::{Deserialize, Serialize};

/// Represents an interval, using **included** minimal and maximal numbers.
#[derive(Debug, Serialize, Deserialize)]
pub struct ParameterInterval<T> {
    pub min: T,
    pub max: T,
}

/// Parameters of the generator.
#[derive(Debug, Serialize, Deserialize)]
pub struct GenerationParameters {
    /// Interval of sub topology to generate, hard constraint
    pub sub_topology_count: ParameterInterval<usize>,
    /// Interval number of node to generate, hard constraint
    pub node_count: ParameterInterval<usize>,
    /// Interval number of subnet to generate, hard constraint
    pub subnet_count: ParameterInterval<usize>,
    /// Target depth of the topology tree.
    pub tree_depth: usize,
    /// List of services to include in the topology.
    pub services: Vec<Service>,
}

/// A service to include in the topology (e.g. http server, mailing server...).)
#[derive(Debug, Serialize, Deserialize)]
pub struct Service {
    // TODO(db)
}
