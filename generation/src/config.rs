use pnet::util::MacAddr;
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
            OS::Linux => 65, // FIXME: 65 so it is detected by iptables rules
            OS::Windows => 128,
        }
    }
}

#[derive(Deserialize, Debug)]
struct Interface {
    os: Option<OS>,
    mac: Option<String>,
    ip: String,
    provides: Option<Vec<u16>>,
    uses: Option<Vec<u16>>,
}

// TODO: passer en copy directement ?
#[derive(Debug, Clone)]
pub struct Hosts {
    hosts_pairs: HashMap<u16, Vec<(Ipv4Addr, Ipv4Addr)>>,
    os: HashMap<Ipv4Addr, OS>,
    mac_addr: HashMap<Ipv4Addr, MacAddr>,
}

impl Hosts {
    pub fn get_default_ttl(&self, ip: &Ipv4Addr) -> u8 {
        // by default, assume Linux
        self.os
            .get(ip)
            .map(|os| os.get_default_ttl())
            .unwrap_or(OS::Linux.get_default_ttl())
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

    pub fn get_mac(&self, ip: &Ipv4Addr) -> &MacAddr {
        self.mac_addr.get(ip).unwrap()
    }
}

pub fn import_config(config: &str) -> Hosts {
    let mut table: HashMap<String, Vec<HashMap<String, Vec<Interface>>>> =
        toml::from_str(config).expect("Ill-formed configuration file");
    let hosts_toml = table.remove("hosts").expect("No host in the config file!");
    let mut provides: HashMap<u16, Vec<Ipv4Addr>> = HashMap::new();
    let mut uses: HashMap<u16, Vec<Ipv4Addr>> = HashMap::new();
    let mut os: HashMap<Ipv4Addr, OS> = HashMap::new();
    let mut mac_addr: HashMap<Ipv4Addr, MacAddr> = HashMap::new();
    for mut host in hosts_toml {
        for iface in host.remove("interfaces").expect("Host without interface!") {
            let ip_toml = iface
                .ip
                .parse()
                .expect("Cannot parse into an IPv4 address!");
            os.insert(ip_toml, iface.os.unwrap_or(OS::Linux));
            // use a default mac if it is not defined
            mac_addr.insert(
                ip_toml,
                iface
                    .mac
                    .unwrap_or("00:00:00:00:00:00".to_string())
                    .parse()
                    .expect("Cannot parse into a MAC address!"),
            );
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
    log::info!("Environment configuration loaded");
    Hosts {
        hosts_pairs,
        os,
        mac_addr,
    }
}
