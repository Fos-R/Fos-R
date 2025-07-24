#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

use core::{mem, net::Ipv4Addr, slice};

use aya_ebpf::{
    bindings::xdp_action::{self, XDP_PASS},
    macros::xdp,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use checksum::Checksum;
use network_types::{eth::EthHdr, ip::Ipv4Hdr, tcp::TcpHdr};

mod checksum;

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
    unsafe { *ipv4_header }.frag_off[0] & 0b1000_0000 > 0
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

unsafe fn update_ipv4_checksum(ipv4_header: *mut Ipv4Hdr) {
    // First, set the checksum to 0, to compute the new one
    unsafe {
        (*ipv4_header).set_checksum(0);
    }
    let header = unsafe { *ipv4_header };
    let mut checksum = Checksum::new();
    checksum.add_bytes(&[header.ihl() | (header.version() << 4) & 0xf0]);
    checksum.add_bytes(&[header.tos]);
    checksum.add_bytes(&header.tot_len);
    checksum.add_bytes(&header.id);
    checksum.add_bytes(&header.frag_off);
    checksum.add_bytes(&[header.ttl]);
    checksum.add_bytes(&[header.proto as u8]);
    checksum.add_bytes(&header.src_addr);
    checksum.add_bytes(&header.dst_addr);
    unsafe {
        (*ipv4_header).set_checksum(u16::from_be_bytes(checksum.checksum()));
    }
}

unsafe fn update_tcp_checksum(
    ctx: XdpContext,
    ipv4_header: *const Ipv4Hdr,
    tcp_header: *mut TcpHdr,
) -> Result<(), ()> {
    // First, set the checksum to 0, to compute the new one
    unsafe {
        (*tcp_header).check = 0;
    }
    let ip = unsafe { *ipv4_header };
    let tcp = unsafe { *tcp_header };

    let mut checksum = Checksum::new();

    // Add pseudo IP header
    checksum.add_bytes(&ip.src_addr);
    checksum.add_bytes(&ip.dst_addr);
    checksum.add_bytes(&[0, ip.proto as u8]);

    // Add whole TCP header (with checksum to 0)
    let tcp_slice = unsafe { slice::from_raw_parts(tcp_header as *const u8, TcpHdr::LEN) };
    checksum.add_bytes(tcp_slice);

    // Check if there is TCP header options
    let tcp_hdr_len = (tcp.doff() * 4) as usize;
    info!(&ctx, "tcp hdr len: {}", tcp_hdr_len);
    // if tcp_hdr_len > TcpHdr::LEN {
    //     let tcp_options_len = tcp_hdr_len - TcpHdr::LEN;
    //     let tcp_options: *mut u8 =
    //         unsafe { mut_ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN + TcpHdr::LEN)? };
    //     let tcp_options_slice =
    //         unsafe { slice::from_raw_parts(tcp_options as *const u8, tcp_options_len) };
    //     checksum.add_bytes(tcp_options_slice);
    // }

    // Add TCP payload
    let tcp_len = ip.total_len() as usize - Ipv4Hdr::LEN;
    let tcp_data_len = tcp_len - tcp_hdr_len;
    checksum.add_bytes(&[(tcp_len >> 8) as u8, (tcp_len & 0xff) as u8]);
    info!(&ctx, "tcp data len: {}", tcp_data_len);
    // if tcp_data_len > 0 {
    //     let tcp_data: *mut u8 = unsafe {
    //         mut_ptr_at(
    //             &ctx,
    //             EthHdr::LEN + Ipv4Hdr::LEN + ((*tcp_header).doff() * 4) as usize,
    //         )?
    //     };
    //     let tcp_data_slice = unsafe { slice::from_raw_parts(tcp_data as *const u8, tcp_data_len) };
    //     checksum.add_bytes(tcp_data_slice);
    // }

    unsafe {
        (*tcp_header).check = u16::from_ne_bytes(checksum.checksum());
    }

    Ok(())
}

/// Main function, where all the processing is happening.
fn try_fosr_ebpf(ctx: XdpContext) -> Result<u32, ()> {
    // info!(&ctx, "Got a new packet");

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
            unsafe { (*ipv4_header).set_dst_addr(Ipv4Addr::new(1, 2, 3, 4)) };

            info!(
                &ctx,
                "New packet: {} TO {}",
                unsafe { *ipv4_header }.src_addr(),
                unsafe { *ipv4_header }.dst_addr(),
            );

            // Recalculate the checksum of the packet (since the destination address changed)
            unsafe { update_ipv4_checksum(ipv4_header) };

            // Update TCP/UDP checksums
            if let network_types::ip::IpProto::Tcp = unsafe { *ipv4_header }.proto {
                // Parse TCP
                let tcp_header: *mut TcpHdr =
                    unsafe { mut_ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)? };

                // Recalculate the checksum of the packet (since the destination address changed)
                unsafe { update_tcp_checksum(ctx, ipv4_header, tcp_header)? };
            }
        }
    }

    // We always accept the packet
    Ok(XDP_PASS)
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

/// To not break "cargo b" workspace compilation
#[cfg(all(not(test), target_os = "none"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

/// To not break "cargo b" workspace compilation
#[cfg(any(test, not(target_os = "none")))]
fn main() {}

#[cfg(test)]
mod tests {
    use network_types::{eth::EthHdr, ip::Ipv4Hdr};

    use crate::update_ipv4_checksum;

    #[test]
    fn test_ipv4_checksum_compute() {
        unsafe {
            let mut ipv4_syn_packet: [u8; 60] = [
                0xc0, 0x47, 0xe, 0x1b, 0xbf, 0xae, 0xb8, 0x27, 0xeb, 0x70, 0xdf, 0xae, 0x8, 0x0,
                0x45, 0x0, 0x0, 0x28, 0x83, 0x69, 0x80, 0x0, 0x40, 0x6, 0xf6, 0x12, 0xc0, 0xa8,
                0x0, 0x2, 0xc0, 0xa8, 0x0, 0x1, 0x8c, 0x70, 0x7, 0x5b, 0x81, 0x3, 0xc8, 0x1b, 0x20,
                0x32, 0x1b, 0x7a, 0x50, 0x10, 0xff, 0xff, 0x15, 0xea, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0,
            ];

            let ipv4_header: *mut Ipv4Hdr =
                (ipv4_syn_packet.as_mut_ptr().byte_add(EthHdr::LEN)) as _;
            let old_checksum = (*ipv4_header).checksum();

            println!("Old checksum: {:#04X?}", (*ipv4_header).check);

            (*ipv4_header).set_checksum(0);
            assert_eq!((*ipv4_header).checksum(), 0);

            update_ipv4_checksum(ipv4_header);

            let new_checksum = (*ipv4_header).checksum();
            println!("New checksum: {:#04X?}", (*ipv4_header).check);

            assert_eq!(
                old_checksum, new_checksum,
                "Checksums not equal, even if the packet is the same"
            );
        }
    }
}
