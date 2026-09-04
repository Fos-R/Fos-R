//! UI constants for consistent styling across the application
//!
//! This module centralizes all UI-related constants to ensure:
//! - Consistent spacing, sizing, and colors across the app
//! - Easy theme adjustments in one place
//! - Self-documenting code with named constants

// ============================================================================
// SPACING
// ============================================================================

/// Extra small spacing (px)
pub const SPACING_XS: f32 = 2.0;

/// Small spacing (px)
pub const SPACING_SM: f32 = 4.0;

/// Medium spacing (px)
pub const SPACING_MD: f32 = 6.0;

/// Large spacing (px)
pub const SPACING_LG: f32 = 8.0;

/// Extra large spacing (px)
pub const SPACING_XL: f32 = 12.0;

/// Extra extra large spacing (px)
pub const SPACING_XXL: f32 = 15.0;

/// Negative extra small spacing (px) for pulling elements closer together
pub const SPACING_NEGATIVE_XS: f32 = -2.0;

// ============================================================================
// TYPOGRAPHY
// ============================================================================

/// Small text size (px)
pub const TEXT_SIZE_SM: f32 = 12.0;

/// Medium text size (px)
pub const TEXT_SIZE_MD: f32 = 13.0;

/// Default text size (px)
pub const TEXT_SIZE_DEFAULT: f32 = 14.0;

/// Large text size (px)
pub const TEXT_SIZE_LG: f32 = 16.0;

/// Icon size for startup cards and major UI elements (px)
pub const ICON_SIZE_LG: f32 = 28.0;

// ============================================================================
// BUTTONS
// ============================================================================

/// Standard button height (px)
pub const BUTTON_HEIGHT: f32 = 24.0;

/// Small button minimum width (px) - Stop, Save, Open
pub const BUTTON_MIN_WIDTH_SM: f32 = 75.0;

/// Large button minimum width (px) - Generate
pub const BUTTON_MIN_WIDTH_LG: f32 = 85.0;

/// Tab button padding (horizontal, vertical) in the top bar
pub const TAB_BUTTON_PADDING: (f32, f32) = (40.0, 2.0);

// ============================================================================
// PANELS & MODALS
// ============================================================================

/// Small modal width (px) - close confirmation
#[cfg(not(target_arch = "wasm32"))]
pub const MODAL_WIDTH_SM: f32 = 370.0;

/// Default modal width (px) - startup
pub const MODAL_WIDTH_MD: f32 = 400.0;

/// Node info modal width (px)
pub const NODE_MODAL_WIDTH: f32 = 250.0;

/// Panel inner margin (horizontal, vertical) for top panel
pub const PANEL_INNER_MARGIN: (i8, i8) = (4, 3);

/// Bottom bar inner margin (horizontal, vertical)
pub const BOTTOM_BAR_INNER_MARGIN: (i8, i8) = (8, 4);

/// Options panel inner margin (horizontal, vertical)
pub const OPTIONS_PANEL_INNER_MARGIN: (i8, i8) = (8, 8);

// ============================================================================
// WINDOW DIMENSIONS (native builds)
// ============================================================================

/// Default window width (px)
#[cfg(not(target_arch = "wasm32"))]
pub const WINDOW_DEFAULT_WIDTH: f32 = 1200.0;

/// Default window height (px)
#[cfg(not(target_arch = "wasm32"))]
pub const WINDOW_DEFAULT_HEIGHT: f32 = 1000.0;

/// Minimum window width (px)
#[cfg(not(target_arch = "wasm32"))]
pub const WINDOW_MIN_WIDTH: f32 = 550.0;

/// Minimum window height (px)
#[cfg(not(target_arch = "wasm32"))]
pub const WINDOW_MIN_HEIGHT: f32 = 500.0;

// ============================================================================
// ZOOM
// ============================================================================

/// Minimum zoom level (fraction)
pub const ZOOM_MIN: f32 = 0.8;

/// Maximum zoom level (fraction) for native builds.
/// This avoids for instance the protocols legend (graph view) or the navbar buttons to overflow.
#[cfg(not(target_arch = "wasm32"))]
pub const ZOOM_MAX: f32 = 1.9;

/// Maximum zoom level (fraction) for WASM builds.
/// This avoids for instance the protocols legend (graph view) or the navbar buttons to overflow.
#[cfg(target_arch = "wasm32")]
pub const ZOOM_MAX: f32 = 1.5;

/// Zoom step increment (fraction)
pub const ZOOM_STEP: f32 = 0.1;

/// Default zoom offset from 1.0 for native builds
#[cfg(not(target_arch = "wasm32"))]
pub const ZOOM_OFFSET: f32 = 0.4;

/// Default zoom offset from 1.0 for WASM builds
#[cfg(target_arch = "wasm32")]
pub const ZOOM_OFFSET: f32 = 0.2;

/// Default zoom factor (1.0 + offset)
pub const ZOOM_DEFAULT: f32 = 1.0 + ZOOM_OFFSET;

/// Tooltip delay in seconds
pub const TOOLTIP_DELAY: f32 = 0.1;

// ============================================================================
// STARTUP CARDS
// ============================================================================

/// Startup card height (px)
pub const STARTUP_CARD_INITIAL_HEIGHT: f32 = 100.0;

/// Template card height (px)
pub const STARTUP_CARD_TEMPLATE_HEIGHT: f32 = 125.0;

/// Number of columns in initial startup modal
pub const STARTUP_COLUMNS_INITIAL: usize = 2;

/// Number of columns in template selection modal
pub const STARTUP_COLUMNS_TEMPLATES: usize = 3;

// ============================================================================
// ABOUT TAB
// ============================================================================

// /// Logo max width in about tab (px)
// pub const LOGO_MAX_WIDTH: f32 = 350.0;

/// Logo max height in about tab (px)
pub const LOGO_MAX_HEIGHT: f32 = 70.0;

// ============================================================================
// GENERATION OPTIONS
// ============================================================================

/// Number of columns in generation options
pub const GENERATION_OPTIONS_COLUMNS: usize = 2;

/// Column 1 minimum width (duration & time options)
pub const GENERATION_COL1_MIN_WIDTH: f32 = 280.0;

/// Column 2 minimum width (seed & advanced options)
pub const GENERATION_COL2_MIN_WIDTH: f32 = 200.0;

/// Duration text field width
pub const DURATION_TEXT_WIDTH: f32 = 80.0;

/// Seed input field width
pub const SEED_INPUT_WIDTH: f32 = 120.0;

/// Timezone picker width
pub const TIMEZONE_PICKER_WIDTH: f32 = 160.0;

/// Timezone popup maximum height
pub const TIMEZONE_POPUP_MAX_HEIGHT: f32 = 450.0;

/// Timezone list maximum height
pub const TIMEZONE_LIST_MAX_HEIGHT: f32 = 400.0;

// ============================================================================
// MULTI-SELECT PICKER
// ============================================================================

/// Default width for the multi-select picker popup.
pub const MULTI_SELECT_PICKER_WIDTH: f32 = 200.0;

// ============================================================================
// SEARCHABLE COMBO
// ============================================================================

/// Default width for the combo button.
pub const DEFAULT_COMBO_WIDTH: f32 = 160.0;

/// Default maximum height for the popup area.
pub const DEFAULT_COMBO_POPUP_MAX_HEIGHT: f32 = 250.0;

/// Default maximum height for the scrollable list.
pub const DEFAULT_COMBO_LIST_MAX_HEIGHT: f32 = 200.0;

// ============================================================================
// VISUALIZATION: NODE SIZING
// ============================================================================

/// Minimum radius for graph nodes (px) - starting size for all nodes
pub const NODE_RADIUS_MIN: f32 = 15.0;

/// Maximum radius for graph nodes (px) - cap to prevent oversized nodes
pub const NODE_RADIUS_MAX: f32 = 25.0;

/// Radius increase per flow (px) - controls how fast nodes grow with traffic
pub const NODE_FLOW_SCALE_FACTOR: f32 = 0.3;

// ============================================================================
// VISUALIZATION: EDGE SIZING
// ============================================================================

/// Minimum width for graph edges (px) - inactive edges are invisible
pub const EDGE_WIDTH_MIN: f32 = 0.0;

/// Maximum width for graph edges (px) - cap to prevent oversized edges
pub const EDGE_WIDTH_MAX: f32 = 3.0;

/// Width increase per flow (px) - controls how fast edges grow with traffic
pub const EDGE_FLOW_SCALE: f32 = 0.2;

/// Arrow size at edge endpoints (px) - indicates direction of traffic
pub const EDGE_ARROW_SIZE: f32 = 16.0;

/// Arrow angle in radians (30 degrees) - PI/6
pub const EDGE_ARROW_ANGLE_RAD: f32 = std::f32::consts::PI / 6.0;

// ============================================================================
// VISUALIZATION: PLAYBACK SPEED
// ============================================================================

/// Available playback speed steps for visualization
pub const PLAYBACK_SPEED_STEPS: &[f32] = &[0.25, 0.5, 0.75, 1.0, 1.5, 2.0, 3.0, 4.0];

/// Epsilon for comparing playback speed values (to handle floating point precision)
pub const PLAYBACK_SPEED_EPSILON: f32 = 0.01;

// ============================================================================
// VISUALIZATION: LAYOUT & DISPLAY
// ============================================================================

/// Angular gap between clusters in radial layout (radians)
pub const CLUSTER_GAP_RAD: f32 = 0.05;

/// Graph layout radius multiplier for cluster mode (scales with subnet count)
pub const GRAPH_LAYOUT_CLUSTER_RADIUS_MULTIPLIER: f32 = 82.5;

/// Graph layout radius base offset for cluster mode
pub const GRAPH_LAYOUT_CLUSTER_RADIUS_BASE: f32 = 82.5;

/// Graph layout radius multiplier for flat mode (scales with node count)
pub const GRAPH_LAYOUT_FLAT_RADIUS_MULTIPLIER: f32 = 60.0;

/// Graph layout radius base offset for flat mode
pub const GRAPH_LAYOUT_FLAT_RADIUS_BASE: f32 = 60.0;

/// Fit to screen padding with subnet zones (fraction of screen)
pub const FIT_TO_SCREEN_PADDING_WITH_ZONES: f32 = 0.3;

/// Fit to screen padding in flat mode
pub const FIT_TO_SCREEN_PADDING_FLAT: f32 = 0.15;

// ============================================================================
// VISUALIZATION: SUBNET ZONES
// ============================================================================

/// Base padding around subnet zone bounding box (canvas px)
pub const ZONE_PAD_BASE: f32 = 40.0;

/// Extra horizontal padding for zone labels on left/right/bottom (canvas px)
pub const ZONE_PAD_LABEL: f32 = 25.0;

/// Top padding reduction (canvas px)
pub const ZONE_PAD_TOP_INSET: f32 = 15.0;

/// Zone rectangle corner rounding radius (canvas px)
pub const ZONE_RECT_ROUNDING: f32 = 6.0;

/// Zone border stroke width (canvas px)
pub const ZONE_BORDER_STROKE_WIDTH: f32 = 1.0;

/// Golden ratio conjugate (phi - 1 = 1/phi), used for distinct hue distribution.
pub const GOLDEN_RATIO_CONJUGATE: f32 = 0.618_034;

/// HSL saturation for colored subnet zones in dark mode
pub const ZONE_COLOR_SATURATION_DARK: f32 = 0.40;

/// HSL lightness for colored subnet zones in dark mode
pub const ZONE_COLOR_LIGHTNESS_DARK: f32 = 0.35;

/// HSL saturation for colored subnet zones in light mode
pub const ZONE_COLOR_SATURATION_LIGHT: f32 = 0.35;

/// HSL lightness for colored subnet zones in light mode
pub const ZONE_COLOR_LIGHTNESS_LIGHT: f32 = 0.70;

/// Alpha for subnet zone fills (0-255)
pub const ZONE_COLOR_ALPHA: u8 = 45;

/// Base timeout for active links display (ms), adjusted by speed.
/// Controls how long links stay in active state.
pub const ACTIVE_LINK_BASE_TIMEOUT_MS: f32 = 500.0;

/// Overlay margin from screen edges (px)
pub const OVERLAY_MARGIN: f32 = 5.0;

/// Legend icon size (px) - for node/edge legend icons
pub const LEGEND_ICON_SIZE: f32 = 12.0;

/// Legend marker radius (px) - for edge protocol color dots
pub const LEGEND_MARKER_RADIUS: f32 = 5.0;

// ============================================================================
// TIMING (frames)
// ============================================================================

/// Quick delay for UI state transitions (frames)
pub const DELAY_FRAMES_QUICK: u8 = 2;

/// Normal delay for UI state transitions (frames)
pub const DELAY_FRAMES_NORMAL: u8 = 10;

// ============================================================================
// INFO ICON & TOOLTIPS
// ============================================================================

/// Info icon spacing adjustment (negative to pull closer)
pub const INFO_ICON_SPACING: f32 = -4.0;

/// Info icon size
pub const INFO_ICON_SIZE: f32 = 14.0;

/// Info tooltip maximum width (px)
pub const INFO_TOOLTIP_MAX_WIDTH: f32 = 300.0;

// ============================================================================
// TEXT EDITOR
// ============================================================================

/// Default number of rows for multiline text editors
pub const TEXT_EDIT_DEFAULT_ROWS: usize = 3;

/// Number of rows for YAML editor
pub const YAML_EDITOR_ROWS: usize = 20;

/// Icon column width in YAML editor
pub const YAML_ICON_COL_WIDTH: f32 = 20.0;

/// Gutter padding in YAML editor
pub const YAML_GUTTER_PADDING: f32 = 6.0;

// ============================================================================
// TOGGLE COMPONENT
// ============================================================================

/// Toggle frame inner margin
pub const TOGGLE_INNER_MARGIN: f32 = 3.0;

/// Toggle item spacing
pub const TOGGLE_ITEM_SPACING: f32 = 3.0;

// ============================================================================
// INDENTATION
// ============================================================================

/// Standard indentation for nested content (px)
pub const INDENT_STANDARD: f32 = 16.0;
