//! Run module: combines live visualization and PCAP generation in a single tab.

mod config_handling;
mod flow_processing;
mod generation_options;
mod state;
mod tab;

pub use state::RunState;
pub use tab::show_run_tab_content;
