//! Library for high-quality, high-throughput synthetic network traffic generation
//! This library is notably used by the binary Fos-R, but can be used freely.

/// Network and host configuration
pub mod config;
/// Structures used throughout the library
pub mod structs;
/// Generation statistics
pub mod ui;

/// ICMP-specific fonctions
mod icmp;
/// TCP-specific fonctions
mod tcp;
/// UDP-specific fonctions
mod udp;

/// Metadata of ICMP packet
pub use icmp::ICMPPacketInfo;
/// Metadata of TCP packet
pub use tcp::TCPPacketInfo;
/// Metadata of UDP packet
pub use udp::UDPPacketInfo;

/// Extraction flow statistics from pcap
pub mod pcap2flow;

/// Timestamp generation
pub mod stage0;

/// Flow statistics generation
pub mod stage1;

/// Packet metadata generation
pub mod stage2;

/// Full packet generation
pub mod stage3;

/// Network injection
pub mod inject;
