//! Sub Topology

use std::{collections::HashMap, net::Ipv4Addr};

use include_dir::include_dir;
use serde::{Deserialize, Serialize};

use crate::{
    OS,
    topo::config::{NodeType, Service, SubTopologyParameters},
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
        for node in nodes.iter() {
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
    include_dir!("$CARGO_MANIFEST_DIR/subtopo")
        .files()
        .map(|f: &include_dir::File| f.contents_utf8().unwrap().to_string())
        .map(|s: String| {
            SubTopology::new(serde_yaml::from_str(&s).expect("Failed to parse sub topology config"))
                .unwrap()
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
            os: Default::default(),
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
