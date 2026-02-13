# Fos-R GUI

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
cargo run -p fosr-gui -r
```
This compiles and launches the native GUI.

#### macOS Bundling

```shell
# Install `cargo-bundle`
cargo install cargo-bundle
# Bundle in a .app
cargo bundle -p fosr-gui -r -f osx
```

### Web (WASM)

#### Step 0: Requirements
You need to have the wasm32 toolchain and the `wasm-bindgen` CLI installed:
```shell
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli
```

#### Step 1: Compile to WASM
```shell
cargo build -p fosr-gui -r --target wasm32-unknown-unknown --no-default-features
```
Output: `Fos-R/target/wasm32-unknown-unknown/release/fosr_gui.wasm`

#### Step 2: Generate JavaScript Glue
```shell
wasm-bindgen --out-dir public --target web target/wasm32-unknown-unknown/release/fosr_gui.wasm --no-typescript
```
Generates in `Fos-R/public/`:
- `fosr_gui.js` - JavaScript glue code
- `fosr_gui_bg.wasm` - WASM binary

### Step 3: Embedding in the HTML file

#### HTML Structure
```html
<div>
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
    }
    run();
</script>
```

### Step 4: Serve with an HTTP server
Here is an example using `http-server`:
```shell
# Install http-server
npm install -g http-server

# Serve from project root
http-server ./public -p 8080
```