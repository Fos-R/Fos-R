//! Host validation: IP/MAC format, conflicts, and type/service consistency.

use crate::shared::config::model::{Configuration, Host};
use crate::shared::constants::network::{MAC_ADDRESS_PARTS, MAC_PART_LENGTH};
use std::collections::HashMap;

/// Counts of IP and MAC address occurrences across all hosts.
pub type AddressCounts = (HashMap<String, usize>, HashMap<String, usize>);

/// Count IP and MAC addresses across all hosts in the configuration.
///
/// Returns a tuple of (ip_counts, mac_counts) used for duplicate detection.
pub fn count_addresses(config: &Configuration) -> AddressCounts {
    let mut ip_counts: HashMap<String, usize> = HashMap::new();
    let mut mac_counts: HashMap<String, usize> = HashMap::new();

    for host in &config.hosts {
        for iface in &host.interfaces {
            *ip_counts.entry(iface.ip_addr.clone()).or_insert(0) += 1;
            if let Some(mac) = &iface.mac_addr {
                *mac_counts.entry(mac.clone()).or_insert(0) += 1;
            }
        }
    }

    (ip_counts, mac_counts)
}

/// Validate a host configuration for correctness.
pub fn validate_host(
    host: &Host,
    ip_counts: &HashMap<String, usize>,
    mac_counts: &HashMap<String, usize>,
) -> Vec<String> {
    let mut errors = Vec::new();

    if host.interfaces.is_empty() {
        errors.push("Missing interface".to_string());
    }

    for iface in &host.interfaces {
        if iface.ip_addr.parse::<std::net::IpAddr>().is_err() {
            errors.push("Invalid IP format".to_string());
        } else if ip_counts.get(&iface.ip_addr).copied().unwrap_or(0) > 1 {
            errors.push("IP conflict".to_string());
        }

        if let Some(mac) = &iface.mac_addr {
            if !is_valid_mac(mac) {
                errors.push("Invalid MAC format".to_string());
            } else if mac_counts.get(mac).copied().unwrap_or(0) > 1 {
                errors.push("MAC conflict".to_string());
            }
        }
    }

    if host.r#type.as_deref() == Some("server") {
        let has_service = host.interfaces.iter().any(|i| !i.services.is_empty());
        if !has_service {
            errors.push("Server missing service".to_string());
        }
    }

    if host.r#type.as_deref() == Some("user") {
        if host.client.is_empty() {
            errors.push("Client missing protocols".to_string());
        }
        let has_service = host.interfaces.iter().any(|i| !i.services.is_empty());
        if has_service {
            errors.push("User host should not have services (use type: server)".to_string());
        }
    }

    errors.dedup();
    errors
}

/// Returns true if any host in the model has validation errors.
pub fn has_model_errors(model: &Configuration) -> bool {
    let (ip_counts, mac_counts) = count_addresses(model);
    model
        .hosts
        .iter()
        .any(|host| !validate_host(host, &ip_counts, &mac_counts).is_empty())
}

/// Check MAC format (ex: 00:14:2A:3F:47:D8)
fn is_valid_mac(mac: &str) -> bool {
    let parts: Vec<&str> = mac.split(':').collect();
    if parts.len() != MAC_ADDRESS_PARTS {
        return false;
    }
    parts
        .iter()
        .all(|p| p.len() == MAC_PART_LENGTH && u8::from_str_radix(p, 16).is_ok())
}
