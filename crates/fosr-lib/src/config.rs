use pnet::util::MacAddr;
use serde::Deserialize;

use std::collections::HashMap;
use std::collections::HashSet;
use std::net::Ipv4Addr;

use crate::structs::*;

#[derive(Debug)]
/// The configuration file of the network and the hosts
pub struct Configuration {
    // TODO: faire du tri dans ce qui n’est pas utile
    /// The metadata of the configuration
    pub metadata: Metadata,
    /// The list of hosts
    pub hosts: Vec<Host>,
    /// A hashmap that maps an IP to a MAC address (if it is defined in the config file)
    pub mac_addr_map: HashMap<Ipv4Addr, MacAddr>,
    /// A hashmap that maps an IP to an OS (if it is defined in the config file)
    pub os_map: HashMap<Ipv4Addr, OS>,
    /// The usages of each IP address
    pub usages_map: HashMap<Ipv4Addr, f64>,
    /// The list of "users" IPs
    pub users: Vec<Ipv4Addr>,
    /// The list of "servers" IPs
    pub servers: Vec<Ipv4Addr>,
    /// The list of services proposed in the configuration
    pub services: Vec<L7Proto>,
    /// Overridden listening ports
    pub open_ports: HashMap<(Ipv4Addr, L7Proto), u16>,
    servers_per_service: HashMap<L7Proto, Vec<Ipv4Addr>>,
    users_per_service: HashMap<L7Proto, Vec<Ipv4Addr>>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct ConfigurationYaml {
    pub metadata: Metadata,
    pub hosts: Vec<Host>,
}

impl From<ConfigurationYaml> for Configuration {
    fn from(c: ConfigurationYaml) -> Self {
        let users: Vec<Ipv4Addr> = c
            .hosts
            .iter()
            .filter_map(|h| match h.host_type {
                HostType::User => Some(h.get_ip_addr()),
                HostType::Server => None,
            })
            .flatten()
            .collect();
        let servers: Vec<Ipv4Addr> = c
            .hosts
            .iter()
            .filter_map(|h| match h.host_type {
                HostType::Server => Some(h.get_ip_addr()),
                HostType::User => None,
            })
            .flatten()
            .collect();
        let mut os_map: HashMap<Ipv4Addr, OS> = HashMap::new();
        let mut usages_map: HashMap<Ipv4Addr, f64> = HashMap::new();
        for host in c.hosts.iter() {
            for interface in host.interfaces.iter() {
                os_map.insert(interface.ip_addr, host.os);
                usages_map.insert(interface.ip_addr, host.usage);
            }
        }

        let mut mac_addr_map: HashMap<Ipv4Addr, MacAddr> = HashMap::new();
        let mut services: HashSet<L7Proto> = HashSet::new();
        let mut servers_per_service: HashMap<L7Proto, Vec<Ipv4Addr>> = HashMap::new();
        let mut users_per_service: HashMap<L7Proto, Vec<Ipv4Addr>> = HashMap::new();
        let mut open_ports: HashMap<(Ipv4Addr, L7Proto), u16> = HashMap::new();

        for interface in c.hosts.iter().flat_map(|h| &h.interfaces) {
            if let Some(mac_addr) = interface.mac_addr {
                mac_addr_map.insert(interface.ip_addr, mac_addr);
            }
            for k in interface.open_ports.keys() {
                open_ports.insert(
                    (interface.ip_addr, *k),
                    *interface.open_ports.get(k).unwrap(),
                );
            }
            for s in interface.services.iter() {
                services.insert(*s);
                let v = servers_per_service.entry(*s).or_default();
                v.push(interface.ip_addr);
            }
        }
        for host in c.hosts.iter() {
            if let Some(client) = &host.client {
                // if a list is defined, then this host will only use these services
                for s in client {
                    if services.contains(s) {
                        for interface in host.interfaces.iter() {
                            users_per_service
                                .entry(*s)
                                .or_default()
                                .push(interface.ip_addr)
                        }
                    } else {
                        log::warn!(
                            "There is a client of {s:?}, but that service is not proposed by any server"
                        );
                    }
                }
            } else {
                // otherwise, use all available services
                for s in services.iter() {
                    for interface in host.interfaces.iter() {
                        users_per_service
                            .entry(*s)
                            .or_default()
                            .push(interface.ip_addr)
                    }
                }
            }
        }

        for service in services.iter() {
            assert!(servers_per_service.contains_key(service));
            assert!(users_per_service.contains_key(service));
        }

        Configuration {
            metadata: c.metadata,
            hosts: c.hosts,
            os_map,
            usages_map,
            mac_addr_map,
            users,
            servers,
            services: services.into_iter().collect(),
            servers_per_service,
            users_per_service,
            open_ports,
        }
    }
}

impl Configuration {
    /// Get the list of servers that provide a service
    pub fn get_servers_per_service(&self, service: &L7Proto) -> Vec<Ipv4Addr> {
        self.servers_per_service
            .get(service)
            .unwrap_or(&vec![])
            .clone()
    }

    /// Get the list of users that uses a service
    pub fn get_users_per_service(&self, service: &L7Proto) -> Vec<Ipv4Addr> {
        self.users_per_service
            .get(service)
            .unwrap_or(&vec![])
            .clone()
    }
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
/// Metadata of the configuration file
pub struct Metadata {
    /// The title of the config file
    pub title: String,
    /// The description of the config file
    pub desc: Option<String>,
    /// The author of the config file
    pub author: Option<String>,
    /// The "last modified" date of the config file
    pub date: Option<String>,
    /// The user-defined version of the config file
    pub version: Option<String>,
    /// The lib-defined format version of the config file
    pub format: Option<u64>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
enum HostType {
    Server,
    User,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
#[serde(from = "HostYaml")]
/// A host in the network
pub struct Host {
    /// Its hostname
    pub hostname: Option<String>,
    /// Its OS
    pub os: OS,
    /// Its usage. 1 is standard, less than 1 is less usage than standard, more than 1 is more usage than standrad
    pub usage: f64,
    client: Option<Vec<L7Proto>>, // we keep the option here, because there is a difference
    // between an empty list (no service is used) and nothing
    // (default services are used)
    host_type: HostType,
    /// Its interfaces
    pub interfaces: Vec<Interface>,
}

impl Host {
    /// Get the list of IP addresses of an host. Cannot be empty.
    pub fn get_ip_addr(&self) -> Vec<Ipv4Addr> {
        self.interfaces.iter().map(|i| i.ip_addr).collect()
    }
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct HostYaml {
    hostname: Option<String>,
    os: Option<OS>,
    usage: Option<f64>,
    client: Option<Vec<L7Proto>>,
    #[serde(rename = "type")]
    host_type: Option<HostType>,
    interfaces: Vec<Interface>,
}

impl From<HostYaml> for Host {
    fn from(h: HostYaml) -> Self {
        let host_type = h.host_type.unwrap_or(
            // if there is at least one service, the type is "server"
            if h.interfaces.iter().any(|i| !i.services.is_empty()) {
                HostType::Server
            } else {
                HostType::User
            },
        );
        Host {
            hostname: h.hostname,
            os: h.os.unwrap_or(OS::Linux),
            usage: h.usage.unwrap_or(1.0),
            host_type,
            interfaces: h.interfaces,
            client: h.client,
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
#[serde(try_from = "InterfaceYaml")]
/// A network interface
pub struct Interface {
    /// Its MAC address
    pub mac_addr: Option<MacAddr>,
    /// The services it provides (may be empty)
    pub services: Vec<L7Proto>,
    /// Its IP address
    pub ip_addr: Ipv4Addr,
    /// The open ports of services, if they are not the default one
    pub open_ports: HashMap<L7Proto, u16>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct InterfaceYaml {
    mac_addr: Option<String>,
    services: Option<Vec<String>>,
    ip_addr: String,
}

impl TryFrom<InterfaceYaml> for Interface {
    type Error = String;

    fn try_from(i: InterfaceYaml) -> Result<Self, String> {
        let mut open_ports: HashMap<L7Proto, u16> = HashMap::new();
        let mut services = vec![];
        for s in i.services.unwrap_or_default() {
            let v: Vec<String> = s.as_str().split(':').map(|s| s.to_string()).collect();
            assert!(!v.is_empty() && v.len() <= 2);
            let service: L7Proto = v[0].clone().try_into()?;
            if v.len() == 2 {
                open_ports.insert(
                    service,
                    v[1].parse::<u16>().expect("Cannot parse the port in {s}"),
                );
            }
            services.push(service);
        }

        Ok(Interface {
            mac_addr: i
                .mac_addr
                .map(|s| s.parse().expect("Cannot parse MAC address")),
            ip_addr: i.ip_addr.parse().expect("Cannot parse IP address"),
            services,
            open_ports,
        })
    }
}

/// Import a configuration from a string. The string can be either in JSON or YAML format (the
/// truth is that YAML is a superset of JSON).
pub fn import_config(config_string: &str) -> Configuration {
    let config: Configuration = serde_yaml::from_str::<ConfigurationYaml>(config_string)
        .expect("Cannot parse the configuration file")
        .into();
    log::info!("\"{}\" successfully loaded", config.metadata.title);
    log::trace!("Configuration: {config:?}");
    config
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_simple() {
        let config = import_config(
            r#"
metadata:
  title: Sample configuration
hosts:
  - interfaces:
      - services:
          - https
          - ssh
        ip_addr: 192.168.0.8
  - interfaces:
      - ip_addr: 192.168.0.9
"#,
        );
        // TODO tester la config chargée
    }

    #[test]
    fn test_config_complex() {
        let config = import_config(
            r#"
metadata:
  title: Sample configuration # Mandatory. The title of the configuration file.
  desc: A sample configuration file to show all the different available fields # Optional. A description of the configuration file.
  author: Jane Doe # Optional. Author of the file.
  date: 2025/11/05 # Optional. Last modification date.
  version: 0.1.0 # Optional. The version number of this configuration file. Format is free.
  format: 1 # Reserved for now. The version will be bumped when the format changes.

hosts:
  - hostname: host1 # Optional. The hostname of the host.
    os: Linux # Optional (default value: Linux). The OS of the host
    usage: 0.8 # Optional (default value: 1.0). The usage intensity of the host. 1 is the baseline, < 1 means less usage than usual, and > 1 means higher usage
    type: server  # Optional (default value: "server" if there is at least one service, "user" otherwise). Whether this host is used by a user and is a server. Can be either "server" or "user"
    client: # Optional (default value: all available services if type is "user", none otherwise). Specify what services the host is a client of.
        - http
        - https
        - ssh
    interfaces:
      - mac_addr: 00:14:2A:3F:47:D8 # Optional. The MAC address of that interface
        services: # Optional (default value: empty list). The list of available services
          - http  # an HTTP server
          - https # an HTTPS server
          - ssh   # an SSH server
        ip_addr: 192.168.0.8 # Mandatory. The IP address of this interface.
      - ip_addr: 192.168.0.9 # This host has another interface that does not provide any service
  - interfaces:
      - ip_addr: 192.168.0.11 # Another host with a single interface
"#,
        );
        println!("{config:?}");
    }

    #[test]
    fn test_config_json() {
        let config = import_config(
            r#"
{
    "metadata": {
        "title": "Sample JSON configuration",
        "desc": "A sample configuration file to show all the different available fields",
        "author": "Jane Doe",
        "date": "2025/11/05",
        "version": "0.1.0",
        "format": 1
    },
    "hosts": [
        {
            "hostname": "host1",
            "os": "Linux",
            "usage": 0.8,
            "type": "server",
            "client": [
                "http",
                "https",
                "ssh"
            ],
            "interfaces": [
                {
                    "mac_addr": "00:14:2A:3F:47:D8",
                    "services": [
                        "http",
                        "https",
                        "ssh"
                    ],
                    "ip_addr": "192.168.0.8"
                },
                {
                    "ip_addr": "192.168.0.9"
                }
            ]
        },
        {
            "interfaces": [
                {
                    "ip_addr": "192.168.0.11"
                }
            ]
        }
    ]
}"#,
        );
        println!("{config:?}");
    }
}
