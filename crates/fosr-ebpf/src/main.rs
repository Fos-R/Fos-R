#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

use core::mem;

use aya_ebpf::{
    bindings::xdp_action::{self, XDP_PASS},
    macros::xdp,
    programs::XdpContext,
};
use network_types::{eth::EthHdr, ip::Ipv4Hdr};

#[xdp]
pub fn fosr_ebpf(ctx: XdpContext) -> u32 {
    match try_fosr_ebpf(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

/// Get the value of the Fos-R flag from ipv4 header.
///
/// # Parameters
///
/// - `ipv4_header`: IPV4 header of the packet.
#[inline(always)]
unsafe fn get_fosr_flag(ipv4_header: *const Ipv4Hdr) -> bool {
    unsafe { *ipv4_header }.frag_flags() & 0b100 > 0
}

/// Get a mutable pointer to a zone of memory at a specific offset.
///
/// # Parameters
///
/// - `ctx`: XDP context, to retrieve the data buffer (to offset from).
/// - `offset`: The offset at which the zone of memory can be found in the packet data.
///
/// # Returns
///
/// A mutable pointer to the memory zone corresponding to packet data + offset.
#[inline(always)]
unsafe fn mut_ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    let ptr = (start + offset) as *mut T;
    Ok(unsafe { &mut *ptr })
}

/// Main function, where all the processing is happening.
fn try_fosr_ebpf(ctx: XdpContext) -> Result<u32, ()> {
    // We parse the ethernet header first (mutable)
    let ethernet_header: *mut EthHdr = unsafe { mut_ptr_at(&ctx, 0)? };
    // Fos-R only supports IPv4
    if let Ok(network_types::eth::EtherType::Ipv4) = unsafe { *ethernet_header }.ether_type() {
        // Retrieve the packet header
        let ipv4_header: *const Ipv4Hdr = unsafe { mut_ptr_at(&ctx, EthHdr::LEN)? };

        // Check if the Fos-R flag is enabled
        if unsafe { get_fosr_flag(ipv4_header) } {
            // This will force the OS network stack to drop the packet:
            // setting MAC destination addresse to broadcast disables kernel’s answer
            unsafe { (*ethernet_header).dst_addr[0] |= 0x01 };
        }
    }

    // We always accept the packet
    Ok(XDP_PASS)
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 20] = *b"Dual MIT/Apache-2.0\0";

/// To not break "cargo b" workspace compilation
#[cfg(all(not(test), target_os = "none"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

/// To not break "cargo b" workspace compilation
#[cfg(any(test, not(target_os = "none")))]
fn main() {}
