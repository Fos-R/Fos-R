#!/bin/bash
# Build and serve the WASM version of Fos-R GUI

set -e

# Check for required commands
for cmd in cargo wasm-bindgen http-server; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "Error: $cmd is not installed."
        exit 1
    fi
done

# Go to project root
cd "$(dirname "$0")/../.."

# Check for index.html
if [ ! -f public/index.html ]; then
    echo "Error: public/index.html not found."
    echo "Run ./public/generate-index-html.sh to create it (requires pandoc)."
    exit 1
fi

echo "Building WASM..."
cargo build -p fosr-gui -r --target wasm32-unknown-unknown --no-default-features

echo "Generating JS glue with wasm-bindgen..."
wasm-bindgen --out-dir public --target web target/wasm32-unknown-unknown/release/fosr_gui.wasm --no-typescript

echo "Starting HTTP server on port 8080..."
http-server ./public -p 8080
