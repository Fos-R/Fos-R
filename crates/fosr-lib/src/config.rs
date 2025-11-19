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
    pub metadata: Metadata,
    pub hosts: Vec<Host>,
    pub mac_addr_map: HashMap<Ipv4Addr, MacAddr>,
    os_map: HashMap<Ipv4Addr, OS>,
    usages_map: HashMap<Ipv4Addr, f64>,
    pub users: Vec<Ipv4Addr>,
    pub servers: Vec<Ipv4Addr>,
    pub services: Vec<L7Proto>,
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

        for interface in c.hosts.iter().flat_map(|h| &h.interfaces) {
            if let Some(mac_addr) = interface.mac_addr {
                mac_addr_map.insert(interface.ip_addr, mac_addr);
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
        }
    }
}

impl Configuration {
    pub fn get_mac(&self, ip: &Ipv4Addr) -> Option<&MacAddr> {
        self.mac_addr_map.get(ip)
    }

    pub fn get_initial_ttl(&self, ip: &Ipv4Addr) -> u8 {
        self.os_map.get(ip).unwrap().get_initial_ttl()
    }

    pub fn get_os(&self, ip: &Ipv4Addr) -> OS {
        *self.os_map.get(ip).unwrap()
    }

    pub fn get_usage(&self, ip: &Ipv4Addr) -> f64 {
        *self.usages_map.get(ip).unwrap()
    }

    pub fn get_servers_per_service(&self, service: &L7Proto) -> Vec<Ipv4Addr> {
        self.servers_per_service
            .get(service)
            .unwrap_or(&vec![])
            .clone()
    }

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
    pub title: String,
    pub desc: Option<String>,
    pub author: Option<String>,
    pub date: Option<String>,
    pub version: Option<String>,
    pub format: Option<u64>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum HostType {
    Server,
    User,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
#[serde(from = "HostYaml")]
pub struct Host {
    pub hostname: Option<String>,
    pub os: OS,
    pub usage: f64,
    pub client: Option<Vec<L7Proto>>, // we keep the option here, because there is a difference
    // between an empty list (no service is used) and nothing
    // (default services are used)
    pub host_type: HostType,
    pub interfaces: Vec<Interface>,
}

impl Host {
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
#[serde(from = "InterfaceYaml")]
pub struct Interface {
    pub mac_addr: Option<MacAddr>,
    pub services: Vec<L7Proto>,
    pub ip_addr: Ipv4Addr,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct InterfaceYaml {
    mac_addr: Option<String>,
    services: Option<Vec<L7Proto>>,
    ip_addr: String,
}

impl From<InterfaceYaml> for Interface {
    fn from(i: InterfaceYaml) -> Self {
        Interface {
            mac_addr: i
                .mac_addr
                .map(|s| s.parse().expect("Cannot parse MAC address")),
            services: i.services.unwrap_or_default(),
            ip_addr: i.ip_addr.parse().expect("Cannot parse IP address"),
        }
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
