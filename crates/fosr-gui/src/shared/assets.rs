//! Embedded assets: images and icons used throughout the application.
//!
//! Centralizes all `include_image!` calls to avoid path issues when files move.

use eframe::egui::{ImageSource, include_image};

// Node icons for graph visualization
pub const IMG_SERVER: ImageSource = include_image!("../../assets/server.png");
pub const IMG_COMPUTER: ImageSource = include_image!("../../assets/computer.png");
pub const IMG_INTERNET: ImageSource = include_image!("../../assets/internet.png");

// Application logo
pub const IMG_LOGO: ImageSource = include_image!("../../../../public/logo.png");
