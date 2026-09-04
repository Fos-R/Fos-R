//! Sub Topology

use include_assets::{NamedArchive, include_dir};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::Ipv4Addr};

use crate::{
    OS,
    topo::config::{NodeType, Service, SubTopologyParameters},
    utils,
};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SubTopology {
    pub name: String,
    pub subnet: Ipv4Addr,
    pub mask: usize,
    pub nodes: Vec<SubTopologyNode>,
    pub router_node: SubTopologyNode,
    pub services: HashMap<Service, bool>,
    pub os: HashMap<OS, bool>,
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum SubTopologyOrInternet {
    SubTopo(SubTopology),
    Internet,
}

impl SubTopology {
    pub fn new(parameters: SubTopologyParameters) -> Result<Self, String> {
        let nodes: Vec<SubTopologyNode> = parameters
            .nodes
            .iter()
            .filter(|node| node.kind == NodeType::Machine)
            .cloned()
            .map(Into::into)
            .collect();
        let router: Vec<SubTopologyNode> = parameters
            .nodes
            .into_iter()
            .filter(|node| node.kind == NodeType::Router)
            .map(Into::into)
            .collect();

        let Some(router_node) = router.first().cloned() else {
            return Err("A sub topology only support one single router".to_string());
        };

        let mut services = HashMap::new();
        let mut os = HashMap::new();

        // Fill hashmaps
        for node in &nodes {
            if let SubTopologyNode::Machine(node) = node {
                for service in &node.services {
                    services.insert(service.clone(), true);
                }

                os.insert(node.os, true);
            }
        }

        Ok(Self {
            name: parameters.name,
            subnet: parameters.subnet,
            mask: parameters.mask,
            nodes,
            router_node,
            services,
            os,
        })
    }

    pub fn is_public(&self) -> bool {
        utils::is_global(&self.subnet)
    }

    pub fn contains_service(&self, service: &Service) -> bool {
        self.services.contains_key(service)
    }

    pub fn contains_os(&self, os: &OS) -> bool {
        self.os.contains_key(os)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum SubTopologyNode {
    Machine(MachineNode),
    Router(RouterNode),
}

impl From<super::config::SubTopologyNode> for SubTopologyNode {
    fn from(value: super::config::SubTopologyNode) -> Self {
        match value.kind {
            super::config::NodeType::Machine => {
                let services = if let Some(service) = value.services {
                    vec![service]
                } else {
                    vec![]
                };

                Self::Machine(MachineNode {
                    name: value.name,
                    address: value.ip,
                    services,
                    os: value.os,
                })
            }
            super::config::NodeType::Router => Self::Router(RouterNode {
                name: value.name,
                address: value.ip,
                interco_address: value.ip, // FIXME(db): This might be a bug
            }),
        }
    }
}

pub fn get_default_subtopos() -> Vec<SubTopology> {
    #[cfg(debug_assertions)]
    let archive = NamedArchive::load(include_dir!("subtopo", compression = "uncompressed"));
    #[cfg(not(debug_assertions))]
    let archive = NamedArchive::load(include_dir!("subtopo", compression = "zstd", level = 19));
    archive
        .assets()
        .filter_map(|(name, f)| {
            if name.ends_with(".yml") {
                Some(
                    SubTopology::new(
                        serde_yaml::from_str(str::from_utf8(f).unwrap())
                            .expect("Failed to parse sub topology config"),
                    )
                    .unwrap(),
                )
            } else {
                None
            }
        })
        .collect()
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MachineNode {
    pub name: String,
    pub address: Ipv4Addr,
    pub services: Vec<Service>,
    pub os: OS,
}

impl MachineNode {
    pub fn new(name: &str, address: Ipv4Addr) -> Self {
        Self {
            name: name.to_string(),
            address,
            services: Vec::new(),
            os: OS::default(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RouterNode {
    pub name: String,
    pub address: Ipv4Addr,
    pub interco_address: Ipv4Addr,
}

impl RouterNode {
    pub fn new(name: &str, address: Ipv4Addr, interco_address: Ipv4Addr) -> Self {
        Self {
            name: name.to_string(),
            address,
            interco_address,
        }
    }
}
