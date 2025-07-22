#![no_std]
#![no_main]

use core::{mem, net::Ipv4Addr};

use aya_ebpf::{
    bindings::xdp_action::{self, XDP_PASS},
    macros::xdp,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use network_types::{eth::EthHdr, ip::Ipv4Hdr};

#[xdp]
pub fn fosr_ebpf(ctx: XdpContext) -> u32 {
    match try_fosr_ebpf(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

/// Get a const pointer to a zone of memory at a specific offset.
///
/// # Parameters
///
/// - `ctx`: XDP context, to retrieve the data buffer (to offset from).
/// - `offset`: The offset at which the zone of memory can be found in the packet data.
///
/// # Returns
///
/// A const pointer to the memory zone corresponding to packet data + offset.
#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    let ptr = (start + offset) as *const T;
    Ok(unsafe { &*ptr })
}

/// Get the value of the Fos-R flag from ipv4 header.
///
/// # Parameters
///
/// - `ipv4_header`: IPV4 header of the packet.
unsafe fn get_fosr_flag(ipv4_header: *const Ipv4Hdr) -> bool {
    unsafe { *ipv4_header }.frag_off[0] & 0b100 > 0
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
    info!(&ctx, "Got a new packet");

    // We parse the ethernet header first
    let ethernet_header: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    if let network_types::eth::EtherType::Ipv4 = unsafe { *ethernet_header }.ether_type {
        // Retrieve the packet header (mutable)
        let ipv4_header: *mut Ipv4Hdr = unsafe { mut_ptr_at(&ctx, EthHdr::LEN)? };

        // Check if the Fos-R flag is enabled
        if unsafe { get_fosr_flag(ipv4_header) } {
            info!(
                &ctx,
                "Got Fos-R packet: {} TO {}",
                unsafe { *ipv4_header }.src_addr(),
                unsafe { *ipv4_header }.dst_addr(),
            );

            // This will force the OS network stack to drop/not respond to the packet
            unsafe { *ipv4_header }.set_dst_addr(Ipv4Addr::new(1, 2, 3, 4));
        }
    }

    // We always accept the packet
    Ok(XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
