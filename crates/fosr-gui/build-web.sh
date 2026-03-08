#!/bin/bash
# Build and serve the WASM version of Fos-R GUI

set -e

# Go to project root
cd "$(dirname "$0")/../.."

echo "Building WASM..."
cargo build -p fosr-gui -r --target wasm32-unknown-unknown --no-default-features

echo "Generating JS glue with wasm-bindgen..."
wasm-bindgen --out-dir public --target web target/wasm32-unknown-unknown/release/fosr_gui.wasm --no-typescript

echo "Starting HTTP server on port 8080..."
http-server ./public -p 8080
