use crate::structs::*;

pub mod fast;
pub use fast::start_fast;
pub mod reliable;
pub use reliable::start_reliable;

#[cfg(all(
    any(target_os = "windows", target_os = "linux"),
    feature = "ebpf",
    feature = "net_injection"
))]
pub mod ebpf;
#[cfg(all(target_os = "linux", feature = "iptables", feature = "net_injection"))]
pub mod iptables;

pub trait NetEnabler: Clone + std::marker::Send + 'static {
    // is this packet sent by Fos-R ?
    fn is_packet_relevant(&self, flags: u8) -> bool;

    // should we send the packet without waiting for any answer?
    fn is_fast(&self) -> bool;

    // close the connection
    fn close_session(&self, f: &FlowId);

    // set-up the connection
    fn open_session(&self, f: &FlowId);
}

#[derive(Debug, Clone)]
// the dummy net enabler is used when no network injection is performed
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
