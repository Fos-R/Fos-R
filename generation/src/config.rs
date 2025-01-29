use rand_core::*;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::Ipv4Addr;

#[derive(Deserialize, Debug, Clone, Copy)]
enum OS {
    Linux,
    Windows,
}

impl OS {
    fn get_default_ttl(&self) -> u8 {
        match self {
            OS::Linux => 64,
            OS::Windows => 128,
        }
    }
}

#[derive(Deserialize, Debug)]
struct Interface {
    os: Option<OS>,
    ip: String,
    provides: Option<Vec<u16>>,
    uses: Option<Vec<u16>>,
}

#[derive(Debug, Clone)]
pub struct Hosts {
    hosts_pairs: HashMap<u16, Vec<(Ipv4Addr, Ipv4Addr)>>,
    os: HashMap<Ipv4Addr, OS>,
}

impl Hosts {
    pub fn get_default_ttl(&self, ip: &Ipv4Addr) -> Option<u8> {
        self.os.get(ip).map(|os| os.get_default_ttl())
    }

    pub fn get_src_and_dst_ip(
        &self,
        rng: &mut impl RngCore,
        dst_port: u16,
    ) -> Option<(Ipv4Addr, Ipv4Addr)> {
        self.hosts_pairs
            .get(&dst_port)
            .map(|v| v[(rng.next_u32() as usize) % v.len()])
    }
}

pub fn import_config(config: &str) -> Hosts {
    let mut table: HashMap<String, Vec<HashMap<String, Vec<Interface>>>> =
        toml::from_str(config).expect("Ill-formed configuration file");
    let hosts_toml = table.remove("hosts").expect("No host in the config file!");
    let mut provides: HashMap<u16, Vec<Ipv4Addr>> = HashMap::new();
    let mut uses: HashMap<u16, Vec<Ipv4Addr>> = HashMap::new();
    let mut os: HashMap<Ipv4Addr, OS> = HashMap::new();
    for mut host in hosts_toml {
        for iface in host.remove("interfaces").expect("Host without interface!") {
            let ip_toml = iface
                .ip
                .parse()
                .expect("Cannot parse into an IPv4 address!");
            os.insert(ip_toml, iface.os.unwrap_or(OS::Linux));
            let provides_toml = iface.provides.unwrap_or_default();
            for port in provides_toml {
                let current_ips = provides.get_mut(&port);
                if let Some(vec) = current_ips {
                    vec.push(ip_toml);
                } else {
                    provides.insert(port, vec![ip_toml]);
                }
            }
            let uses_toml = iface.uses.unwrap_or_default();
            for port in uses_toml {
                let current_ips = uses.get_mut(&port);
                if let Some(vec) = current_ips {
                    vec.push(ip_toml);
                } else {
                    uses.insert(port, vec![ip_toml]);
                }
            }
        }
    }

    let mut hosts_pairs = HashMap::new();
    for (port, ip1_vec) in uses {
        if let Some(ip2_vec) = provides.remove(&port) {
            let mut pairs_port = Vec::new();
            for ip1 in ip1_vec.iter() {
                for ip2 in ip2_vec.iter() {
                    if ip1 != ip2 {
                        // we avoid src_ip = dst_ip
                        pairs_port.push((*ip1, *ip2));
                    }
                }
            }
            hosts_pairs.insert(port, pairs_port);
        }
    }
    Hosts { hosts_pairs, os }
}
