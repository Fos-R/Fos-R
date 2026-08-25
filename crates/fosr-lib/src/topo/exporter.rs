//! Exporter
//!
//! Convert internal topology structures to Fos-R `Network`.

use crate::L7Proto;
use crate::network::{
    HostType, HostYaml, InterfaceYaml, Metadata, Network, NetworkYaml, SubNetworkYaml, next_ui_id,
};
use crate::topo::sub_topology::{SubTopology, SubTopologyNode};

impl From<Vec<SubTopology>> for NetworkYaml {
    fn from(topology: Vec<SubTopology>) -> Self {
        let mut has_service = false;
        let mut has_user = false;

        let mut networks = Vec::with_capacity(topology.len());
        for st in &topology {
            let mut hosts = Vec::with_capacity(st.nodes.len() + 1);

            if let SubTopologyNode::Router(router) = &st.router_node {
                let mut interfaces = vec![InterfaceYaml {
                    ip_addr: router.address.to_string(),
                    mac_addr: None,
                    services: None,
                    uses: Some(vec![]),
                }];
                if router.interco_address != router.address {
                    interfaces.push(InterfaceYaml {
                        ip_addr: router.interco_address.to_string(),
                        mac_addr: None,
                        services: None,
                        uses: Some(vec![]),
                    });
                }

                hosts.push(HostYaml {
                    ui_id: next_ui_id(),
                    hostname: Some(router.name.clone()),
                    os: None,
                    host_type: Some(HostType::User),
                    interfaces,
                });
            }

            for node in &st.nodes {
                let SubTopologyNode::Machine(machine) = node else {
                    continue;
                };

                let services: Vec<String> = machine
                    .services
                    .iter()
                    .flat_map(|s| Vec::<L7Proto>::from(s.clone()))
                    .map(|p| format!("{p:?}").to_lowercase())
                    .collect();

                let is_server = !services.is_empty();
                has_service |= is_server;
                has_user |= !is_server;

                hosts.push(HostYaml {
                    ui_id: next_ui_id(),
                    hostname: Some(machine.name.clone()),
                    os: Some(machine.os),
                    host_type: Some(if is_server {
                        HostType::Server
                    } else {
                        HostType::User
                    }),
                    interfaces: vec![InterfaceYaml {
                        ip_addr: machine.address.to_string(),
                        mac_addr: None,
                        services: if services.is_empty() {
                            None
                        } else {
                            Some(services)
                        },
                        uses: if is_server { Some(vec![]) } else { None },
                    }],
                });
            }

            networks.push(SubNetworkYaml {
                ui_id: next_ui_id(),
                subnet: st.subnet,
                mask: st.mask as u8,
                name: st.name.clone(),
                hosts,
            });
        }

        if has_service && !has_user {
            let first_server = networks
                .iter_mut()
                .flat_map(|n| n.hosts.iter_mut())
                .find(|h| {
                    h.interfaces
                        .iter()
                        .any(|i| i.services.as_ref().is_some_and(|s| !s.is_empty()))
                });
            if let Some(host) = first_server {
                if let Some(iface) = host.interfaces.first_mut() {
                    iface.uses = None;
                }
            }
        }

        NetworkYaml {
            metadata: Metadata {
                title: "Generated topology".to_string(),
                desc: Some("Automatically generated from topology generator".to_string()),
                author: None,
                date: None,
                version: None,
                format: None,
            },
            networks,
            internet: vec![],
        }
    }
}

impl From<Vec<SubTopology>> for Network {
    fn from(topology: Vec<SubTopology>) -> Self {
        NetworkYaml::from(topology).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::topo::config::SubTopologyParameters;
    use std::net::Ipv4Addr;

    #[test]
    fn sub_topology_vec_to_network() {
        let st = r#"
mask: 24
name: st1
nodes:
- ip: 192.168.0.1
  name: r1_1
  type: router
- ip: 192.168.0.2
  name: n1_2
  os: linux
  services: ftp_server
  type: machine
- ip: 192.168.0.3
  name: n1_3
  os: windows
  type: machine
subnet: 192.168.0.0
"#;
        let parsed: SubTopologyParameters =
            serde_yaml::from_str(st).expect("Failed to parse sub topology");
        let topology = vec![SubTopology::new(parsed).expect("Failed to build sub topology")];

        let network_yaml = NetworkYaml::from(topology);
        let yaml_string =
            serde_yaml::to_string(&network_yaml).expect("NetworkYaml should serialize");
        println!("{yaml_string}");

        let network: Network = network_yaml.into();
        assert_eq!(network.networks.len(), 1 + 1);
        assert_eq!(network.servers.len(), 1);
        assert_eq!(network.users.len(), 2);
        assert!(!network.services.is_empty());

        let router_ip = Ipv4Addr::new(192, 168, 0, 1);
        assert!(network.users.contains(&router_ip));
        assert!(network.os_map.contains_key(&router_ip));
        for service in &network.services {
            assert!(!network.get_users_per_service(service).contains(&router_ip));
        }
    }
}
