//! Centralized color constants for consistent styling across the application.
//!
//! This module centralizes all color constants to ensure:
//! - Consistent colors across the app
//! - Easy theme adjustments in one place
//! - Self-documenting code with named colors

use eframe::egui::Color32;
use fosr_lib::structs::L7Proto;

// ============================================================================
// SEMANTIC COLORS (UI state)
// ============================================================================

/// Error color (red) - for validation errors and error messages
pub const COLOR_ERROR: Color32 = Color32::from_rgb(220, 50, 50);

/// Warning color (amber/orange) - for warnings and unsaved changes
pub const COLOR_WARNING: Color32 = Color32::from_rgb(230, 160, 0);

/// Success color (light green) - for success states and progress bars
pub const COLOR_SUCCESS: Color32 = Color32::from_rgb(144, 238, 144);

/// Stop/Danger color (red) - for stop buttons and dangerous actions
pub const COLOR_STOP: Color32 = Color32::from_rgb(200, 80, 80);

// ============================================================================
// TEXT COLORS
// ============================================================================

/// Muted/secondary text color (gray) - for labels and secondary info
pub const COLOR_TEXT_MUTED: Color32 = Color32::GRAY;

// ============================================================================
// VISUALIZATION: NODE ICONS
// ============================================================================

/// Icon tint for dark mode - gray instead of pure white
pub const COLOR_ICON_TINT_DARK: Color32 = Color32::from_rgb(180, 180, 180);

/// Icon tint for light mode - gray instead of pure black
pub const COLOR_ICON_TINT_LIGHT: Color32 = Color32::from_rgb(40, 40, 40);

// ============================================================================
// VISUALIZATION: EDGE STATES
// ============================================================================

/// Inactive edge color (light gray)
pub const COLOR_EDGE_INACTIVE: Color32 = Color32::from_rgb(200, 200, 200);

// ============================================================================
// VISUALIZATION: PROTOCOL COLORS
// ============================================================================

/// HTTP protocol color (blue)
pub const COLOR_PROTOCOL_HTTP: Color32 = Color32::from_rgb(52, 152, 219);

/// HTTPS protocol color (green)
pub const COLOR_PROTOCOL_HTTPS: Color32 = Color32::from_rgb(46, 204, 113);

/// SSH protocol color (purple)
pub const COLOR_PROTOCOL_SSH: Color32 = Color32::from_rgb(155, 89, 182);

/// DNS protocol color (orange)
pub const COLOR_PROTOCOL_DNS: Color32 = Color32::from_rgb(230, 126, 34);

/// SMTP protocol color (yellow)
pub const COLOR_PROTOCOL_SMTP: Color32 = Color32::from_rgb(241, 196, 15);

/// DHCP protocol color (teal)
pub const COLOR_PROTOCOL_DHCP: Color32 = Color32::from_rgb(0, 188, 212);

/// Telnet protocol color (salmon)
pub const COLOR_PROTOCOL_TELNET: Color32 = Color32::from_rgb(233, 30, 99);

/// IMAPS protocol color (indigo)
pub const COLOR_PROTOCOL_IMAPS: Color32 = Color32::from_rgb(63, 81, 181);

/// MQTT protocol color (lime)
pub const COLOR_PROTOCOL_MQTT: Color32 = Color32::from_rgb(139, 195, 74);

/// KMS protocol color (deep orange)
pub const COLOR_PROTOCOL_KMS: Color32 = Color32::from_rgb(255, 87, 34);

/// MulticastDNS protocol color (pink)
pub const COLOR_PROTOCOL_MDNS: Color32 = Color32::from_rgb(240, 98, 146);

/// FTP protocol color (??)
// TODO(pf): set the color, currently using cyan
pub const COLOR_PROTOCOL_FTP: Color32 = Color32::from_rgb(0, 229, 255);

/// FTP protocol color (??)
// TODO(pf): set the color, currently using cyan
pub const COLOR_PROTOCOL_LDAP: Color32 = Color32::from_rgb(0, 229, 255);

/// NTP protocol color (cyan)
pub const COLOR_PROTOCOL_NTP: Color32 = Color32::from_rgb(0, 229, 255);

/// Unknown protocol color (green)
pub const COLOR_PROTOCOL_UNKNOWN: Color32 = Color32::from_rgb(0, 205, 154);

// ============================================================================
// VISUALIZATION: SUBNET ZONE COLORS
// ============================================================================

/// RGB components for the uniform subnet zone fill color
pub const ZONE_UNIFORM_RGB: (u8, u8, u8) = (52, 119, 235);

/// Brighten amount for zone borders and labels in dark mode
pub const ZONE_ACCENT_BRIGHTEN: u8 = 150;

/// Alpha for zone borders and labels in dark mode
pub const ZONE_ACCENT_ALPHA_DARK: u8 = 200;

/// Alpha for zone borders and labels in light mode
pub const ZONE_ACCENT_ALPHA_LIGHT: u8 = 150;

/// Returns the visualization color for a given L7 protocol.
pub fn color_for_protocol(proto: &L7Proto) -> Color32 {
    match proto {
        L7Proto::HTTP => COLOR_PROTOCOL_HTTP,
        L7Proto::HTTPS => COLOR_PROTOCOL_HTTPS,
        L7Proto::SSH => COLOR_PROTOCOL_SSH,
        L7Proto::DNS => COLOR_PROTOCOL_DNS,
        L7Proto::SMTP => COLOR_PROTOCOL_SMTP,
        L7Proto::DHCP => COLOR_PROTOCOL_DHCP,
        L7Proto::Telnet => COLOR_PROTOCOL_TELNET,
        L7Proto::IMAPS => COLOR_PROTOCOL_IMAPS,
        L7Proto::MQTT => COLOR_PROTOCOL_MQTT,
        L7Proto::KMS => COLOR_PROTOCOL_KMS,
        L7Proto::MulticastDNS => COLOR_PROTOCOL_MDNS,
        L7Proto::FTP => COLOR_PROTOCOL_FTP,
        L7Proto::LDAP => COLOR_PROTOCOL_LDAP,
        L7Proto::NTP => COLOR_PROTOCOL_NTP,
        _ => COLOR_PROTOCOL_UNKNOWN,
    }
}
