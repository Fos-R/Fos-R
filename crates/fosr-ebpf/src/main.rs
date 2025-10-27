#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(target_os = "none")]
pub mod ebpf;
#[cfg(target_os = "none")]
pub use ebpf::*;

/// To not break "cargo b" workspace compilation
#[cfg(all(not(test), target_os = "none"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

/// To not break "cargo b" workspace compilation
#[cfg(any(test, not(target_os = "none")))]
fn main() {}
