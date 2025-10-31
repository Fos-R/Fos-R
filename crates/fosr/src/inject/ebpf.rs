use crate::inject::*;
use aya::Ebpf;
use pnet::datalink;

#[derive(Debug, Clone)]
pub struct EBPFNetEnabler {
    // Params
    fast: bool,
}

impl NetEnabler for EBPFNetEnabler {
    fn is_packet_relevant(&self, flags: u8) -> bool {
        flags & 0b100 > 0 // we know the traffic is tainted
    }
    fn is_fast(&self) -> bool {
        self.fast
    }
    fn close_session(&self, _: &FlowId) {}
    fn open_session(&self, _: &FlowId) {}
    fn get_ttl(&self) -> Option<u8> {
        None
    }
}

/// Load the ebpf XDP program, and attach it to each valid interface used by Fos-R.
///
/// # Parameters
///
/// - `local_interfaces`: List of used (by Fos-R) network interfaces.
fn load_ebpf_program(local_interfaces: &[datalink::NetworkInterface]) {
    use aya::programs::{Xdp, XdpFlags};

    // Retrieve the stored eBPF program that where stored, at compilation, into the binary
    // This only hold a reference, the object is stored by aya (globaly), so no need to store it anywhere,
    // it will not be destroyed at the end of the function
    let mut ebpf =
        aya::Ebpf::load(fosr_ebpf::EBPF_PROGRAM).expect("Couldn't retrieve eBPF program");
    let program: &mut Xdp = ebpf
        .program_mut("fosr_ebpf")
        .expect("Failed to get mut reference of program")
        .try_into()
        .expect("Failed to get Xdp program reference");
    program.load().expect("Failed to load eBPF program");

    // Attach the program to each network interface
    for local_interface in local_interfaces {
        program
            .attach(&local_interface.name, XdpFlags::SKB_MODE)
            .unwrap_or_else(|_| {
                panic!("failed to attach the XDP program on interface {local_interface}")
            });
    }

    // leak the ebpf program so it lives as long as the process
    Box::<Ebpf>::leak(Box::new(ebpf));
}

impl EBPFNetEnabler {
    pub fn new(fast: bool, local_interfaces: &[datalink::NetworkInterface]) -> Self {
        load_ebpf_program(local_interfaces);
        EBPFNetEnabler { fast }
    }
}
