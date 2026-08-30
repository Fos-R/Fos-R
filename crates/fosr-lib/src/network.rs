use crate::structs::{L7Proto, L7ProtoWithPort, OS};
use crate::utils;

use include_dir::Dir;
use include_dir::include_dir;
use pnet::util::MacAddr;
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};

/// Name of the synthetic Internet network.
pub const INTERNET_NETWORK_NAME: &str = "Internet";

pub fn get_default_topologies() -> Vec<NetworkYaml> {
    let d: Dir = include_dir!("$CARGO_MANIFEST_DIR/default_topologies");
    d.files()
        .inspect(|e| {
            log::debug!("Loading default template {:?}", e.path());
        })
        .map(|f: &include_dir::File| reversibly_import_network(f.contents_utf8().unwrap()))
        .collect()
}

/// The configuration file of the network and the hosts
#[derive(Debug)]
pub struct Network {
    /// The metadata of the configuration
    pub metadata: Metadata,

    /// The list of networks
    pub networks: Vec<SubNetwork>,

    /// Whether this network can access the Internet
    pub has_internet_access: bool,

    /// A hashmap that maps an IP to a MAC address (if it is defined in the config file)
    pub mac_addr_map: HashMap<Ipv4Addr, MacAddr>,

    /// A hashmap that maps an IP to an OS (if it is defined in the config file)
    pub os_map: HashMap<Ipv4Addr, OS>,

    /// The list of "users" IPs
    pub users: Vec<Ipv4Addr>,

    /// The list of "servers" IPs
    pub servers: Vec<Ipv4Addr>,

    /// The list of services proposed in the configuration
    pub services: Vec<L7Proto>,

    /// The list of services per server
    pub services_per_server: HashMap<(Ipv4Addr, L7Proto), Vec<L7ProtoWithPort>>,

    /// The list of servers that provide each service
    pub servers_per_service: HashMap<L7Proto, Vec<Ipv4Addr>>,
}

impl Network {
    /// Get all hosts in the configuration.
    pub fn get_hosts(&self) -> Vec<&Host> {
        let out: Vec<&Host> = self.networks.iter().flat_map(|n| n.hosts.iter()).collect();
        out
    }

    /// Get the list of servers that provide a service
    pub fn get_servers_per_service(&self, service: &L7Proto) -> Vec<Ipv4Addr> {
        self.servers_per_service
            .get(service)
            .unwrap_or(&vec![])
            .clone()
    }

}

/// A network in the simulation, containing resolved hosts.
#[derive(Debug)]
pub struct SubNetwork {
    pub subnet: Ipv4Addr,
    pub mask: u8,
    pub name: String,
    pub hosts: Vec<Host>,
}

/// Metadata of the configuration file.
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    /// The title of the config file
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub title: String,

    /// The description of the config file
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desc: Option<String>,

    /// The author of the config file
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,

    /// The "last modified" date of the config file
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,

    /// The user-defined version of the config file
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    /// The lib-defined format version of the config file
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum HostType {
    Server,
    User,
}

/// A host in the network
/// TODO: clean useless attributes
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
#[serde(from = "HostYaml")]
pub struct Host {
    /// Its hostname
    pub hostname: Option<String>,

    /// Its OS
    pub os: OS,

    /// The type of host (server or user)
    pub host_type: HostType,

    /// Its interfaces
    pub interfaces: Vec<Interface>,
}

impl Host {
    /// Get the list of IP addresses of an host.
    pub fn get_ip_addr(&self) -> Vec<Ipv4Addr> {
        self.interfaces.iter().map(|i| i.ip_addr).collect()
    }
}

/// A network interface of an host.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
#[serde(try_from = "InterfaceYaml")]
pub struct Interface {
    /// Its MAC address
    pub mac_addr: Option<MacAddr>,
    /// The services it provides (may be empty)
    pub services: Vec<L7ProtoWithPort>,
    /// Its IP address
    pub ip_addr: Ipv4Addr,
}

/// Global counter for stable UI identifiers (not serialized to YAML).
static NEXT_UI_ID: AtomicU64 = AtomicU64::new(1);

/// Generate a unique UI ID used as a stable key for egui collapsing state.
pub fn next_ui_id() -> u64 {
    NEXT_UI_ID.fetch_add(1, Ordering::Relaxed)
}

/// The YAML-level configuration structure.
/// This is the shared model used for both parsing and serializing config files.
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct NetworkYaml {
    pub metadata: Metadata,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub networks: Vec<SubNetworkYaml>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub internet: Vec<HostYaml>,
}

impl NetworkYaml {
    /// Get total number of hosts across all networks and internet.
    pub fn count_hosts(&self) -> usize {
        self.networks.iter().map(|n| n.hosts.len()).sum::<usize>() + self.internet.len()
    }

    /// Add a new network to the configuration.
    pub fn add_network(&mut self, network: SubNetworkYaml) {
        self.networks.insert(0, network);
    }

    /// Remove a network by index.
    pub fn remove_network(&mut self, idx: usize) {
        if idx < self.networks.len() {
            self.networks.remove(idx);
        }
    }
}

/// YAML-level network representation.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct SubNetworkYaml {
    // This is not serialized in YAML, but created on deserialization as a
    // unique ID to be used in the GUI to uniquely identify UI elements.
    #[serde(skip, default = "next_ui_id")]
    pub ui_id: u64,

    pub subnet: Ipv4Addr,

    pub mask: u8,

    pub name: String,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<HostYaml>,
}

/// YAML-level host representation with String-based fields for editing.
/// TODO: clean useless attributes
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct HostYaml {
    // This is not serialized in YAML, but created on deserialization as a
    // unique ID to be used in the GUI to uniquely identify UI elements.
    #[serde(skip, default = "next_ui_id")]
    pub ui_id: u64,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<OS>,

    // client: Option<Vec<L7Proto>>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub host_type: Option<HostType>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<InterfaceYaml>,
}

impl HostYaml {
    /// Create a new host with a unique UI ID.
    pub fn new() -> Self {
        Self {
            ui_id: NEXT_UI_ID.fetch_add(1, Ordering::Relaxed),
            hostname: None,
            os: None,
            host_type: None,
            interfaces: Vec::new(),
        }
    }
}

impl Default for HostYaml {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Deserialize, Serialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct InterfaceYaml {
    // Required: the IPv4 address of this interface.
    pub ip_addr: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac_addr: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub services: Option<Vec<String>>,
}

impl From<NetworkYaml> for Network {
    fn from(c: NetworkYaml) -> Self {
        // Convert YAML structs to runtime structs
        let internet: Vec<Host> = c.internet.into_iter().map(Host::from).collect();
        let networks_yaml = c.networks;
        let networks: Vec<SubNetwork> = networks_yaml
            .into_iter()
            .map(|n| SubNetwork {
                subnet: n.subnet,
                mask: n.mask,
                name: n.name,
                hosts: n.hosts.into_iter().map(Host::from).collect(),
            })
            .collect();

        let users: Vec<Ipv4Addr> = networks
            .iter()
            .flat_map(|n| &n.hosts)
            .chain(&internet)
            .filter_map(|h| match h.host_type {
                HostType::User => Some(h.get_ip_addr()),
                HostType::Server => None,
            })
            .flatten()
            .collect();
        let servers: Vec<Ipv4Addr> = networks
            .iter()
            .flat_map(|n| &n.hosts)
            .chain(&internet)
            .filter_map(|h| match h.host_type {
                HostType::Server => Some(h.get_ip_addr()),
                HostType::User => None,
            })
            .flatten()
            .collect();
        let mut os_map: HashMap<Ipv4Addr, OS> = HashMap::new();
        for host in networks
            .iter()
            .flat_map(|n| n.hosts.iter())
            .chain(&internet)
        {
            for interface in host.interfaces.iter() {
                os_map.insert(interface.ip_addr, host.os);
            }
        }

        let mut mac_addr_map: HashMap<Ipv4Addr, MacAddr> = HashMap::new();
        let mut services: HashSet<L7Proto> = HashSet::new();
        let mut servers_per_service: HashMap<L7Proto, Vec<Ipv4Addr>> = HashMap::new();
        let mut services_per_server: HashMap<(Ipv4Addr, L7Proto), Vec<L7ProtoWithPort>> =
            HashMap::new();
        let mut users_per_service: HashMap<L7Proto, Vec<Ipv4Addr>> = HashMap::new();

        let mut has_internet_access = false;
        let local_hosts = networks.iter().flat_map(|n| n.hosts.iter());
        for interface in local_hosts.flat_map(|h| &h.interfaces) {
            if utils::is_global(&interface.ip_addr) {
                has_internet_access = true;
                break;
            }
        }

        let all_hosts = internet
            .iter()
            .chain(networks.iter().flat_map(|n| n.hosts.iter()));
        for interface in all_hosts.flat_map(|h| &h.interfaces) {
            if let Some(mac_addr) = interface.mac_addr {
                mac_addr_map.insert(interface.ip_addr, mac_addr);
            }
            // TODO: si protocole pas connu, alors il *faut* mettre le port explicitement (mettre
            // un warning)
            // for k in interface.open_ports.keys() {
            //     open_ports.insert(
            //         (interface.ip_addr, *k),
            //         *interface.open_ports.get(k).unwrap(),
            //     );
            // }
            for s in interface.services.iter() {
                services.insert(s.get_proto());
                let v = servers_per_service.entry(s.get_proto()).or_default();
                v.push(interface.ip_addr);
                let v = services_per_server
                    .entry((interface.ip_addr, s.get_proto()))
                    .or_default();
                v.push(*s);
            }
        }
 
        let all_hosts = internet
            .iter()
            .chain(networks.iter().flat_map(|n| n.hosts.iter()));
        for host in all_hosts {
            for s in services.iter() {
                for interface in host.interfaces.iter() {
                    users_per_service
                        .entry(*s)
                        .or_default()
                        .push(interface.ip_addr)
                }
            }
        }

        for service in services.iter() {
            assert!(servers_per_service.contains_key(service));
            assert!(users_per_service.contains_key(service));
        }

        let mut all_networks = networks;
        if !internet.is_empty() {
            all_networks.push(SubNetwork {
                subnet: Ipv4Addr::UNSPECIFIED, // 0.0.0.0
                mask: 0,
                name: INTERNET_NETWORK_NAME.to_string(),
                hosts: internet,
            });
        }

        Network {
            metadata: c.metadata,
            networks: all_networks,
            os_map,
            mac_addr_map,
            users,
            servers,
            services: services.into_iter().collect(),
            services_per_server,
            servers_per_service,
            has_internet_access,
            // users_per_service,
            // open_ports,
        }
    }
}

impl From<HostYaml> for Host {
    fn from(h: HostYaml) -> Self {
        let host_type = h.host_type.unwrap_or(
            // if there is at least one service, the type is "server"
            if h.interfaces
                .iter()
                .any(|i| i.services.as_ref().is_some_and(|s| !s.is_empty()))
            {
                HostType::Server
            } else {
                HostType::User
            },
        );
        Host {
            hostname: h.hostname,
            os: h.os.unwrap_or(OS::Linux),
            host_type,
            interfaces: h
                .interfaces
                .into_iter()
                .map(Interface::try_from)
                .filter_map(|r| {
                    if let Err(e) = &r {
                        log::warn!("Skipping interface: {e}");
                    }
                    r.ok()
                })
                .collect(),
            // client: h.client,
        }
    }
}

impl TryFrom<InterfaceYaml> for Interface {
    type Error = String;

    fn try_from(i: InterfaceYaml) -> Result<Self, String> {
        // let mut open_ports: HashMap<L7Proto, u16> = HashMap::new();
        let mut services = vec![];
        for s in i.services.unwrap_or_default() {
            let service: L7ProtoWithPort = L7ProtoWithPort::from_str(s.as_str())?;
            services.push(service);
        }

        let mut rng = rand::rng(); //TODO: déterminisme
        let ip_addr = match i.ip_addr.as_str() {
            "auto" => Ipv4Addr::new(0, 0, 0, 0),
            "internet" => Ipv4Addr::new(
                rng.random::<u8>(),
                rng.random::<u8>(),
                rng.random::<u8>(),
                rng.random::<u8>(),
            ), // TODO: ne pas générer complètement au hasard pour éviter les collisions et permettre d'utiliser une seed
            _ => i.ip_addr.parse().expect("Cannot parse IP address"),
        };
        Ok(Interface {
            // uses,
            mac_addr: i
                .mac_addr
                .map(|s| s.parse().expect("Cannot parse MAC address")),
            ip_addr,
            services,
            // open_ports,
        })
    }
}

/// Import a configuration from a string. The string can be either in JSON or YAML format (the
/// truth is that YAML is a superset of JSON).
// TODO: renvoyer un Result
pub fn import_network(config_string: &str) -> Network {
    let config: Network = serde_yaml::from_str::<NetworkYaml>(config_string)
        .expect("Cannot parse the configuration file")
        .into();
    log::info!("\"{}\" successfully loaded", config.metadata.title);
    log::trace!("Network: {config:?}");
    config
}

/// Import a configuration from a string.
pub fn reversibly_import_network(config_string: &str) -> NetworkYaml {
    let config: NetworkYaml = serde_yaml::from_str::<NetworkYaml>(config_string)
        .expect("Cannot parse the configuration file");
    log::info!("\"{}\" successfully loaded", config.metadata.title);
    log::trace!("Network: {config:?}");
    config
}

