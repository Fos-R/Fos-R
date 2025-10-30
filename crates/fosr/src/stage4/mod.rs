use crate::structs::*;

#[cfg(feature = "net_injection")]
/// Fast injection, that does not wait for packet response
pub mod fast;
#[cfg(feature = "net_injection")]
pub use fast::start_fast;
#[cfg(feature = "net_injection")]
/// Reliable injection, that waits for packet response
pub mod reliable;
#[cfg(feature = "net_injection")]
pub use reliable::start_reliable;

#[cfg(all(
    any(target_os = "windows", target_os = "linux"),
    feature = "ebpf",
    feature = "net_injection"
))]
/// Network enabler based on eBPF
pub mod ebpf;
#[cfg(all(target_os = "linux", feature = "iptables", feature = "net_injection"))]
/// Network enable based on iptables
pub mod iptables;

/// A trait for network enablers
pub trait NetEnabler: Clone + std::marker::Send + 'static {
    /// is this packet sent by Fos-R ?
    fn is_packet_relevant(&self, flags: u8) -> bool;

    /// should we send the packet without waiting for any answer?
    fn is_fast(&self) -> bool;

    /// close the connection
    fn close_session(&self, f: &FlowId);

    /// set-up the connection
    fn open_session(&self, f: &FlowId);
}

#[derive(Debug, Clone)]
/// Used when no network injection is performed
pub struct DummyNetEnabler {}

impl NetEnabler for DummyNetEnabler {
    fn is_packet_relevant(&self, _: u8) -> bool {
        false
    }
    fn is_fast(&self) -> bool {
        false
    }
    fn close_session(&self, _: &FlowId) {}
    fn open_session(&self, _: &FlowId) {}
}
