use std::{collections::HashMap, net::Ipv4Addr};

/// Parse the following TOML file
/// [[ip_replacements]]
/// old = "192.168.0.1"
/// new = "192.168.56.101"
/// [[ip_replacements]]
/// old = "192.168.0.2"
/// new = "192.168.56.102"
///
/// into a HashMap<Ipv4Addr, Ipv4Addr>
pub fn parse_config(config_str: &str) -> HashMap<Ipv4Addr, Ipv4Addr> {
    let msg = "Ill-formed configuration file";
    let table: HashMap<String, Vec<HashMap<String, String>>> =
        toml::from_str(config_str).expect(msg);

    let ip_replacements = table
        .get("ip_replacements")
        .expect(msg)
        .iter()
        .map(|entry| {
            let old = entry.get("old").expect(msg).parse().expect(msg);
            let new = entry.get("new").expect(msg).parse().expect(msg);
            (old, new)
        })
        .collect::<HashMap<Ipv4Addr, Ipv4Addr>>();

    ip_replacements
}
