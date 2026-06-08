//! PCAP generation module: core logic, state, validation, and Wireshark integration.

pub mod bottom_panel;
pub mod core;
pub mod options;
pub mod process;
pub mod state;
pub mod validation;
#[cfg(not(target_arch = "wasm32"))]
pub mod wireshark;
