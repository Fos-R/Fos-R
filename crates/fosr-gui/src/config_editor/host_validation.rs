//! Host validation: IP/MAC format, conflicts, subnet placement, and type/service consistency.

use fosr_lib::config::{ConfigurationYaml, HostYaml, NetworkYaml};
use crate::shared::constants::network::{MAC_ADDRESS_PARTS, MAC_PART_LENGTH};
use fosr_lib::config::HostType;
use std::collections::HashMap;
use std::net::Ipv4Addr;

/// Counts of IP and MAC address occurrences across all hosts.
pub type AddressCounts = (HashMap<String, usize>, HashMap<String, usize>);

/// Count IP and MAC addresses across all hosts in the configuration.
///
/// Returns a tuple of (ip_counts, mac_counts) used for duplicate detection.
pub fn count_addresses(config: &ConfigurationYaml) -> AddressCounts {
    let mut ip_counts: HashMap<String, usize> = HashMap::new();
    let mut mac_counts: HashMap<String, usize> = HashMap::new();

    for host in config
        .networks
        .iter()
        .flat_map(|n| &n.hosts)
        .chain(&config.internet)
    {
        for interface in &host.interfaces {
            // Skip "auto" and empty IPs - they are placeholders resolved at generation time
            // and should not participate in duplicate detection.
            if !interface.ip_addr.is_empty() && interface.ip_addr != "auto" {
                *ip_counts.entry(interface.ip_addr.clone()).or_insert(0) += 1;
            }
            if let Some(mac) = &interface.mac_addr {
                *mac_counts.entry(mac.clone()).or_insert(0) += 1;
            }
        }
    }

    (ip_counts, mac_counts)
}

/// Validate a host configuration for correctness.
pub fn validate_host(
    host: &HostYaml,
    ip_counts: &HashMap<String, usize>,
    mac_counts: &HashMap<String, usize>,
) -> Vec<String> {
    let mut errors = Vec::new();

    if host.interfaces.is_empty() {
        errors.push("Missing interface".to_string());
    }

    for interface in &host.interfaces {
        if interface.ip_addr != "auto" && interface.ip_addr.parse::<Ipv4Addr>().is_err() {
            errors.push("Invalid IP format".to_string());
        } else if ip_counts.get(&interface.ip_addr).copied().unwrap_or(0) > 1 {
            errors.push("IP conflict".to_string());
        }

        if let Some(mac) = &interface.mac_addr {
            if !validate_mac_format(mac) {
                errors.push("Invalid MAC format".to_string());
            } else if mac_counts.get(mac).copied().unwrap_or(0) > 1 {
                errors.push("MAC conflict".to_string());
            }
        }
    }

    if host.host_type == Some(HostType::Server) {
        let has_service = host
            .interfaces
            .iter()
            .any(|i| i.services.as_ref().map_or(false, |s| !s.is_empty()));
        if !has_service {
            errors.push("Server missing service".to_string());
        }
    }

    if host.host_type == Some(HostType::User) {
        let has_uses = host
            .interfaces
            .iter()
            .any(|i| i.uses.as_ref().map_or(false, |u| !u.is_empty()));
        if !has_uses {
            errors.push("Client missing protocols".to_string());
        }
        let has_service = host
            .interfaces
            .iter()
            .any(|i| i.services.as_ref().map_or(false, |s| !s.is_empty()));
        if has_service {
            errors.push("User host should not have services (use type: server)".to_string());
        }
    }

    errors.dedup();
    errors
}

/// Returns true if any host in the model has validation errors.
pub fn has_model_errors(model: &ConfigurationYaml) -> bool {
    let (ip_counts, mac_counts) = count_addresses(model);
    model
        .networks
        .iter()
        .flat_map(|n| &n.hosts)
        .chain(&model.internet)
        .any(|host| !validate_host(host, &ip_counts, &mac_counts).is_empty())
}

/// Check MAC format (ex: 00:14:2A:3F:47:D8)
fn validate_mac_format(mac: &str) -> bool {
    let parts: Vec<&str> = mac.split(':').collect();
    if parts.len() != MAC_ADDRESS_PARTS {
        return false;
    }
    parts
        .iter()
        .all(|p| p.len() == MAC_PART_LENGTH && u8::from_str_radix(p, 16).is_ok())
}

/// Validate that at least one interface IP falls within the given subnet/mask.
///
/// Returns `None` if OK, or a warning string if the host has no interface in its network.
pub fn validate_host_network_placement(
    host: &HostYaml,
    subnet: Ipv4Addr,
    mask: u8,
) -> Option<String> {
    let subnet_u32 = u32::from(subnet);
    let net_mask = !((1u32 << (32 - mask as u32)) - 1);

    let has_matching_ip = host.interfaces.iter().any(|iface| {
        // "auto" IPs are assigned from the subnet at generation time
        if iface.ip_addr == "auto" {
            return true;
        }
        iface
            .ip_addr
            .parse::<Ipv4Addr>()
            .map(|ip| (u32::from(ip) & net_mask) == (subnet_u32 & net_mask))
            .unwrap_or(false)
    });

    if !has_matching_ip && !host.interfaces.is_empty() {
        Some(format!("No interface in {subnet}/{mask}"))
    } else {
        None
    }
}

/// Check whether two subnets overlap (share at least one address).
///
/// Two subnets overlap when one contains the other. We compare using the
/// *smaller* (less specific) mask - that covers the wider address range.
/// If both addresses share the same prefix up to that mask, they overlap.
///
/// Example: 192.168.1.0/24 vs 192.168.1.128/25
///   min_mask = 24 → net_mask = 0xFFFFFF00
///   192.168.1.0 & 0xFFFFFF00 == 192.168.1.128 & 0xFFFFFF00 → overlap
fn subnets_overlap(a: Ipv4Addr, mask_a: u8, b: Ipv4Addr, mask_b: u8) -> bool {
    let min_mask = mask_a.min(mask_b);
    // Build a bitmask with the top `min_mask` bits set to 1:
    //   32 - min_mask = number of host bits
    //   (1u32 << host_bits) - 1 = host part mask (low bits all 1s, e.g. 0x000000FF for /24)
    //   !(...) = network part mask (high bits all 1s, e.g. 0xFFFFFF00 for /24)
    let net_mask = !((1u32 << (32 - min_mask as u32)) - 1);
    // Zero out the host part of each address; if the network prefixes match, they overlap
    (u32::from(a) & net_mask) == (u32::from(b) & net_mask)
}

/// Collect all `(subnet, mask)` pairs defined in the configuration,
/// excluding a specific network index (used when checking a network against *others*).
pub fn collect_other_subnets(
    networks: &[NetworkYaml],
    exclude_idx: usize,
) -> Vec<(Ipv4Addr, u8)> {
    networks
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != exclude_idx)
        .map(|(_, n)| (n.subnet, n.mask))
        .collect()
}

/// Validate that a network's subnet does not overlap with any other network.
///
/// Returns a list of human-readable warnings (empty if no overlaps found).
pub fn validate_network_subnet_overlap(
    network: &NetworkYaml,
    other_subnets: &[(Ipv4Addr, u8)],
) -> Vec<String> {
    let mut warnings = Vec::new();
    for &(other_subnet, other_mask) in other_subnets {
        if subnets_overlap(network.subnet, network.mask, other_subnet, other_mask) {
            warnings.push(format!(
                "Subnet overlaps with {other_subnet}/{other_mask}"
            ));
        }
    }
    warnings
}

/// Find the next available /24 subnet in the 192.168.X.0 range.
///
/// Scans X from 1 to 254 and returns the first `192.168.X.0` that does not
/// overlap with any existing subnet in the configuration.
pub fn find_available_subnet(networks: &[NetworkYaml]) -> Option<Ipv4Addr> {
    let existing: Vec<(Ipv4Addr, u8)> = networks.iter().map(|n| (n.subnet, n.mask)).collect();

    for x in 1u8..=254 {
        let candidate = Ipv4Addr::new(192, 168, x, 0);
        let overlaps = existing
            .iter()
            .any(|&(s, m)| subnets_overlap(candidate, 24, s, m));
        if !overlaps {
            return Some(candidate);
        }
    }
    None
}
