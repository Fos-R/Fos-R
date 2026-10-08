pub use real_selen::*;

#[cfg(target_arch = "wasm32")]
pub mod wasm_compat {
    pub use web_time::Instant;
}
