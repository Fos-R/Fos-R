mod about;
mod generation;
mod injection;

mod generate;

pub use about::show_about_tab_content;
pub use generation::{GenerationState, show_generation_tab_content};
#[cfg(not(target_arch = "wasm32"))]
pub use injection::show_injection_tab_content;
