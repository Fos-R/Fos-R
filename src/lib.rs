pub mod config;
pub mod structs;
pub mod ui;

mod icmp;
mod tcp;
mod udp;

pub use icmp::ICMPPacketInfo;
pub use tcp::TCPPacketInfo;
pub use udp::UDPPacketInfo;

pub mod replay;
pub mod stage0;
pub mod stage1;
pub mod stage2;
pub mod stage3;
#[cfg(not(target_os = "linux"))]
pub mod stage4 {
    pub struct Stage4 {}
}
#[cfg(target_os = "linux")]
pub mod stage4;
