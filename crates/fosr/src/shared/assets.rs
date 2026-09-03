//! Embedded assets: images and icons used throughout the application.
//!
//! Centralizes all `include_image!` calls. Reduces path issues when files move.

use eframe::egui::{ImageSource, include_image};

// Node icons for graph visualization
pub const IMG_SERVER: ImageSource = include_image!("../../assets/server.png");
pub const IMG_COMPUTER: ImageSource = include_image!("../../assets/computer.png");
pub const IMG_INTERNET: ImageSource = include_image!("../../assets/internet.png");
pub const IMG_ROUTER: ImageSource = include_image!("../../assets/router.png");

// Logos
pub const IMG_LOGO: ImageSource = include_image!("../../../../public/logo.png");
pub const IMG_LOGO_INRIA: ImageSource = include_image!("../../../../public/logo_inria.png");
pub const IMG_LOGO_PIRAT: ImageSource = include_image!("../../../../public/logo_pirat.png");
