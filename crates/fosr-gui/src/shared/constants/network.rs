//! Network-related constants for configuration and visualization

// ============================================================================
// PORTS
// ============================================================================

/// Minimum valid port number
pub const PORT_MIN: u16 = 1;

/// Maximum valid port number
pub const PORT_MAX: u16 = 65535;

/// Default port when service is unknown
pub const PORT_UNSPECIFIED: u16 = 0;

// ============================================================================
// IP ADDRESS RANGES
// ============================================================================

/// Minimum IP octet value for local network (192.168.0.x)
pub const IP_LOCAL_MIN: u8 = 1;

/// Maximum IP octet value for local network (192.168.0.x)
pub const IP_LOCAL_MAX: u8 = 254;

// ============================================================================
// MAC ADDRESS
// ============================================================================

/// Number of bytes in a MAC address
pub const MAC_ADDRESS_BYTES: usize = 6;

/// Number of parts when parsing MAC address (XX:XX:XX:XX:XX:XX)
pub const MAC_ADDRESS_PARTS: usize = 6;

/// Expected length of each MAC address part (2 hex chars)
pub const MAC_PART_LENGTH: usize = 2;

/// MAC address local bit (second character of first octet)
pub const MAC_LOCAL_BIT: u8 = 0x02;

/// MAC address mask for local bit manipulation
pub const MAC_LOCAL_MASK: u8 = 0xFE;

// ============================================================================
// HOST CONFIGURATION DEFAULTS
// ============================================================================

/// Default usage intensity for hosts (1.0 = baseline, <1 = less active, >1 = more active)
pub const HOST_USAGE_DEFAULT: f32 = 1.0;

// ============================================================================
// STREAM TIMING (for visualization)
// ============================================================================

/// Buffer ahead duration in seconds - how far ahead to generate flows
pub const STREAM_BUFFER_AHEAD_SECS: u64 = 5;

/// Check interval in milliseconds - how often to check for flows to emit
pub const STREAM_CHECK_INTERVAL_MS: u64 = 50;

/// Rate limit for generation in milliseconds - prevents CPU spinning
#[cfg(not(target_arch = "wasm32"))]
pub const STREAM_RATE_LIMIT_MS: u64 = 100;

/// Maximum flows generated per cycle (WASM only)
#[cfg(target_arch = "wasm32")]
pub const STREAM_MAX_PER_CYCLE_WASM: usize = 10;
