# Fos-R GUI - Development Notes

## Architecture

### File Structure
```
Fos-R/
├── crates/
│   └── fosr-gui/
│       ├── src/
│       │   ├── main.rs          # Desktop entry point (native binary)
│       │   ├── lib.rs           # Web entry point (WASM export)
│       │   ├── app.rs           # Core application logic (shared)
│       │   └── ui/              # UI components
│       └── Cargo.toml
└── public/
    ├── index.html               # Web interface
    └── (generated WASM and JS files)
```

### How It Works

- `main.rs`: Desktop-only. Runs a native window via `eframe`.
- `lib.rs`: WASM-only. Exports a `start()` function callable from JavaScript.
- `app.rs`: Shared UI logic between desktop and web builds.
- `index.html`: Loads the WASM binary and initializes the app in a canvas element.

## Building & Running

### Desktop (Native)
```shell
cd crates/fosr-gui
cargo run --release
```
This compiles and launches the native GUI.

#### macOS Bundling

```shell
# Install `cargo-bundle`
cargo install cargo-bundle
# Bundle in a .app
cargo bundle --release
```

### Web (WASM)

#### Step 1: Compile to WASM
```shell
cd crates/fosr-gui
cargo build --release --target wasm32-unknown-unknown --no-default-features
```
Output: `Fos-R/target/wasm32-unknown-unknown/release/fosr_gui.wasm`

#### Step 2: Generate JavaScript Glue

You need to have the wasm32 toolchain and the `wasm-bindgen` CLI installed:
```shell
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli
```

```shell
cd ../.. # Back to project root
wasm-bindgen --out-dir public --target web target/wasm32-unknown-unknown/release/fosr_gui.wasm --no-typescript
```
Generates in `Fos-R/public/`:
- `fosr_gui.js` - JavaScript module
- `fosr_gui_bg.wasm` - Optimized WASM binary

### Step 3: Embedding in the HTML file

#### HTML Structure
```html
<div id="canvas-wrapper">
    <div id="loading_text">Loading application...</div>
    <canvas id="fosr_gui_canvas"></canvas>
</div>
```

#### JavaScript
```html
<script type="module">
    import init, { start } from './fosr_gui.js';

    async function run() {
        await init();
        await start('fosr_gui_canvas');

        // Remove loading text
        const loadingText = document.getElementById('loading_text');
        if (loadingText) {
            loadingText.remove();
        }
    }

    run().catch(error => {
        console.error('Failed to start app:', error);
        const loadingText = document.getElementById('loading_text');
        if (loadingText) {
            loadingText.innerHTML = '<p style="color: #e74c3c;">The application crashed. See console.</p>';
        }
    });
</script>
```

### Step 4: Serve with an HTTP server
Here is an example using `http-server`:
```shell
# Install http-server
npm install -g http-server # or pnpm

# Serve from project root
http-server ./public -p 8080
```

Open http://localhost:8080 in your browser.

Note: If the page was previously cached, you may have to do a hard refresh (`Ctrl+Shift+R` / `Cmd+Shift+R`).

## Notes
`eframe_template` suggests using `trunk`, but during my tests:
- I encountered issues with compilation to WASM when using the `release` flag;
- `trunk` seemed to embed additional stuff in the built WASM/JS, which was creating unwanted requests when serving with something different from `trunk serve`;
- `trunk` requires an HTML file to start its build process, and creates a new HTML file where the WASM is linked: there does not seem to be a way to build WASM/JS only. This implies rewiring thing ourselves in our HTML.

Therefore, I changed my approach and chose to go a simpler way, step by step, directly using `cargo` and `wasm-bindgen`.

This made it necessary to separate native and WASM in `main.rs` and `lib.rs` respectively. 

To avoid warnings during compilation, I added a `cargo` _feature_ ("native"), but maybe there's a better way to handle those.
