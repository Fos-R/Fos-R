//! Library for high-quality, high-throughput synthetic network traffic generation
//! This library is notably used by the binary Fos-R, but can be used freely.
// #![warn(missing_docs)]

/// Network and host configuration
pub mod network;
/// Generation statistics
pub mod stats;

#[doc(hidden)]
/// Structures used throughout the library
pub mod structs;

#[doc(inline)]
pub use structs::*;

/// Default models included in the binary
pub mod models;

/// ICMP-specific fonctions
mod icmp;
/// TCP-specific fonctions
mod tcp;
/// UDP-specific fonctions
mod udp;

/// Metadata of ICMP packet
pub use icmp::IcmpPacketInfo;
/// Metadata of TCP packet
pub use tcp::TcpPacketInfo;
/// Metadata of UDP packet
pub use udp::UdpPacketInfo;

/// Utilities
pub mod utils;

/// Timestamp generation
pub mod stage1;

/// Flow statistics generation
pub mod stage2;

/// Packet metadata generation
pub mod stage3;

/// Full packet generation
pub mod stage4;

/// Export to pcap
pub mod export;

/// Capture router received packets
#[cfg(all(target_os = "linux", feature = "net_injection"))]
pub mod capture;
/// Network injection
pub mod inject;
/// Build a network-namespace lab from a topology
#[cfg(all(target_os = "linux", feature = "net_injection"))]
pub mod netns;

/// Network topology generator
pub mod topo;
