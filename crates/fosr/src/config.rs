use serde::Deserialize;
use pnet::util::MacAddr;

use std::net::Ipv4Addr;

use crate::structs::*;

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub metadata: Metadata,
    pub hosts: Vec<Host>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
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
    pub client: Vec<L7Proto>,
    #[serde(rename = "type")]
    pub host_type: HostType,
    pub interfaces: Vec<Interface>,
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
            if h.interfaces
                .iter()
                .any(|i| !i.services.is_empty())
            {
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
            client: h.client.unwrap_or(vec![]),
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
            mac_addr: i.mac_addr.map(|s| s.parse().expect("Cannot parse MAC address")),
            services: i.services.unwrap_or(vec![]),
            ip_addr: i.ip_addr.parse().expect("Cannot parse IP address"),
        }
    }
}

/// Import a configuration from a string. The string can be either in JSON or YAML format.
pub fn import_config(config_string: &str) -> Configuration {
    let config: Configuration =
        serde_yaml::from_str(&config_string).expect("Cannot parse the configuration file");
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
