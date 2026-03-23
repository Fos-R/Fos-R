//! Centralized color constants for consistent styling across the application.
//!
//! This module centralizes all color constants to ensure:
//! - Consistent colors across the app
//! - Easy theme adjustments in one place
//! - Self-documenting code with named colors

use eframe::egui::Color32;

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

/// Other/unknown protocol color (gray)
pub const COLOR_PROTOCOL_OTHER: Color32 = Color32::from_rgb(149, 165, 166);
