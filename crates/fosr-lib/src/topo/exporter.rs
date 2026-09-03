//! Exporter
//!
//! Convert internal topology structures to Fos-R `Network`.

use crate::L7Proto;
use crate::network::{
    HostType, HostYaml, InterfaceYaml, Metadata, Network, NetworkYaml, SubNetworkYaml, next_ui_id,
};
use crate::topo::subtopo::{SubTopologyNode, SubTopologyOrInternet};

impl From<Vec<SubTopologyOrInternet>> for NetworkYaml {
    fn from(topology: Vec<SubTopologyOrInternet>) -> Self {
        let mut networks = Vec::with_capacity(topology.len());
        for st in &topology {
            match st {
                SubTopologyOrInternet::Internet => {
                    // no included in the network file
                }
                SubTopologyOrInternet::SubTopo(st) => {
                    let mut hosts = Vec::with_capacity(st.nodes.len() + 1);

                    if let SubTopologyNode::Router(router) = &st.router_node {
                        let mut interfaces = vec![InterfaceYaml {
                            ip_addr: router.address.to_string(),
                            mac_addr: None,
                            services: None,
                        }];
                        if router.interco_address != router.address {
                            interfaces.push(InterfaceYaml {
                                ip_addr: router.interco_address.to_string(),
                                mac_addr: None,
                                services: None,
                            });
                        }

                        hosts.push(HostYaml {
                            ui_id: next_ui_id(),
                            hostname: Some(router.name.clone()),
                            os: None,
                            host_type: Some(HostType::Router),
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
            }
        }

        NetworkYaml {
            metadata: Metadata {
                title: format!("Synthetic topology with {} subnets", networks.len()),
                desc: Some("Automatically generated with Fos-R topology generator".to_string()),
                author: Some("Fos-R generator".to_string()),
                date: Some(chrono::Local::now().format("%Y-%m-%d").to_string()),
                version: Some("1.0".to_string()),
                format: Some(1),
            },
            networks,
            internet: vec![],
        }
    }
}

impl From<Vec<SubTopologyOrInternet>> for Network {
    fn from(topology: Vec<SubTopologyOrInternet>) -> Self {
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
