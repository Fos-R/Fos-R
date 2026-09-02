//! Configure/Structures

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::{L7Proto, OS};

/// Parameters of the generator.
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct GenerationParameters {
    /// Whether to include at least one public subnet
    pub no_internet_access: bool,
    /// Minimal number of sub topology to generate, hard constraint
    pub minimum_sub_topology: usize,
    /// Minimal number of node to generate, hard constraint
    pub minimum_node_count: usize,
    // /// Target depth of the topology tree
    // pub tree_depth: usize,
    /// List of services to include in the topology
    /// A service to include in the topology (e.g. http server, mailing server...)
    pub services: Vec<Service>,
}

/// Defines a sub topology parameters
#[derive(Debug, Serialize, Deserialize)]
pub struct SubTopologyParameters {
    /// Mask of the subnetwork (e.g. 24 for 255.255.255.0)
    pub mask: usize,
    /// Name of the sub topology.
    pub name: String,
    /// Nodes in the sub topology (e.g. machines, routers...)
    pub nodes: Vec<SubTopologyNode>,
    /// Subnet address of this sub topology
    pub subnet: Ipv4Addr,
    /// A service that is installed on the node
    pub services: Option<Service>,
}

/// Defines a list of sub topology nodes (e.g. machines)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SubTopologyNode {
    /// Name of the node (e.g. hostname)
    pub name: String,
    /// Associated ip
    pub ip: Ipv4Addr,
    /// Operating system used by the node
    #[serde(default)]
    pub os: OS,
    /// Type of the node
    #[serde(rename = "type")]
    pub kind: NodeType,
    /// Service to be present on the machine
    pub services: Option<Service>,
}

/// Type of a node of a sub topology
#[derive(Debug, Serialize, Deserialize, Default, PartialEq, PartialOrd, Clone)]
#[serde(rename_all = "lowercase")]
pub enum NodeType {
    #[default]
    Machine,
    Router,
}

/// A service, installed on a node
#[derive(Debug, Serialize, Deserialize, Clone, Hash, PartialEq, PartialOrd, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Service {
    WebServer,
    FtpServer,
    MailServer,
    CloudStorage,
    LogServer,
    DbmsServer,
    CmsServer,
    ProxyServer,
    LdapServer,
    DnsServer,
    SshServer,
}

impl From<Service> for Vec<L7Proto> {
    fn from(value: Service) -> Self {
        match value {
            Service::FtpServer => vec![L7Proto::FTP],
            Service::MailServer => vec![L7Proto::IMAPS, L7Proto::SMTP],
            Service::LdapServer => vec![L7Proto::LDAP],
            Service::DnsServer => vec![L7Proto::DNS],
            Service::SshServer => vec![L7Proto::SSH],
            Service::WebServer
            | Service::CloudStorage
            | Service::LogServer
            | Service::DbmsServer
            | Service::CmsServer
            | Service::ProxyServer => vec![L7Proto::HTTPS],
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::topo::sub_topology::SubTopology;

    use super::*;

    #[test]
    fn test_config_parsing() {
        let config = r#"
minimum_sub_topology: 2
minimum_node_count: 10
minimum_subnet_count: 2
tree_depth: 0

services:
  - ftp_server
"#;

        let _: GenerationParameters = serde_yaml::from_str(config).expect("Failed to parse config");
    }

    #[test]
    fn test_sub_topology_parsing() {
        let config = r#"
mask: 24
name: st1
nodes:
- ip: 192.168.0.1
  name: r1_1
  type: router
- ip: 192.168.0.2
  name: n1_2
  os: linux
  type: machine
- ip: 192.168.0.3
  name: n1_3
  os: linux
  services: cloud_storage
  type: machine
- ip: 192.168.0.4
  name: n1_4
  os: windows
  type: machine
subnet: 192.168.0.0

"#;

        let _: SubTopologyParameters =
            serde_yaml::from_str(config).expect("Failed to parse config");
    }

    #[test]
    fn test_sub_topology_converter() {
        let config = r#"
mask: 24
name: st1
nodes:
- ip: 192.168.0.1
  name: r1_1
  type: router
- ip: 192.168.0.2
  name: n1_2
  os: linux
  type: machine
- ip: 192.168.0.3
  name: n1_3
  os: linux
  services: cloud_storage
  type: machine
- ip: 192.168.0.4
  name: n1_4
  os: windows
  type: machine
subnet: 192.168.0.0

"#;

        let parsed_config: SubTopologyParameters =
            serde_yaml::from_str(config).expect("Failed to parse config");

        let _ = SubTopology::new(parsed_config)
            .expect("Failed to convert sub topology parameters to sub topology object");
    }
}
