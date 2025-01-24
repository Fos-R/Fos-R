use rand::prelude::*;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::Ipv4Addr;

#[derive(Deserialize, Debug)]
struct Interface {
    ip: String,
    provides: Option<Vec<u16>>,
    uses: Option<Vec<u16>>,
}

#[derive(Debug, Clone)]
pub struct Hosts {
    provides: HashMap<u16, Vec<Ipv4Addr>>,
    uses: HashMap<u16, Vec<Ipv4Addr>>,
}

impl Hosts {
    pub fn get_src_and_dst_ip(
        &self,
        rng: &mut impl RngCore,
        dst_port: u16,
    ) -> (Option<Ipv4Addr>, Option<Ipv4Addr>) {
        // TODO: check they are different!
        (
            self.uses
                .get(&dst_port)
                .map(|vec| vec[(rng.next_u32() as usize) % vec.len()]),
            self.provides
                .get(&dst_port)
                .map(|vec| vec[(rng.next_u32() as usize) % vec.len()]),
        )
    }
}

pub fn import_config(config: &str) -> Hosts {
    let mut table: HashMap<String, Vec<HashMap<String, Vec<Interface>>>> =
        toml::from_str(config).expect("Ill-formed configuration file");

    let hosts_toml = table.remove("hosts").expect("No host in the config file!");
    let mut hosts = Hosts {
        provides: HashMap::new(),
        uses: HashMap::new(),
    };
    for mut host in hosts_toml {
        for iface in host.remove("interfaces").expect("Host without interface!") {
            let ip_toml = iface.ip.parse().expect("Cannot parse into an IPv4 address!");
            let provides_toml = iface.provides.unwrap_or_default();
            for port in provides_toml {
                let current_ips = hosts.provides.get_mut(&port);
                if let Some(vec) = current_ips {
                    vec.push(ip_toml);
                } else {
                    hosts.provides.insert(port, vec![ip_toml]);
                }
            }
            let uses_toml = iface.uses.unwrap_or_default();
            for port in uses_toml {
                let current_ips = hosts.uses.get_mut(&port);
                if let Some(vec) = current_ips {
                    vec.push(ip_toml);
                } else {
                    hosts.uses.insert(port, vec![ip_toml]);
                }
            }
        }
    }
    hosts
}
