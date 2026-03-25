# Fos-R GUI

## Architecture

### Module Overview

| Module              | Purpose                                                       |
|---------------------|---------------------------------------------------------------|
| `app/`              | Core application: tab navigation, startup modal, close dialog |
| `config_editor/`    | Visual and YAML configuration editor                          |
| `run/`              | PCAP generation + live network visualization                  |
| `shared/`           | Reusable: config model, constants, widgets                    |
| `config_templates/` | Pre-built network configuration templates                     |
| `about_tab.rs`      | About page content                                            |

### File Structure

```
Fos-R/
├── crates/
│   └── fosr-gui/
│       ├── src/
│       │   ├── main.rs              # Desktop entry point (native binary)
│       │   ├── lib.rs               # Web entry point (WASM export)
│       │   ├── app/                 # Core application
│       │   ├── config_editor/       # Configuration editor
│       │   ├── run/                 # Generation + visualization
│       │   │   ├── generation/      # PCAP generation logic
│       │   │   └── graph/           # Network graph visualization
│       │   ├── shared/              # Reusable components
│       │   │   ├── config/          # Config model and state
│       │   │   ├── constants/       # Colors, UI constants
│       │   │   └── widgets/         # Reusable UI widgets
│       │   └── config_templates/    # Pre-built templates
│       └── Cargo.toml
└── public/
    ├── index.html                   # Web interface
    └── (generated WASM and JS files)
```

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

Note: the version of the `wasm-bindgen` CLI must match the version of the `wasm-bindgen` crate declared in `Cargo.toml`.

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

#### Step 3: Embedding in the HTML file

##### HTML Structure

```html

<div>
    <canvas id="fosr_gui_canvas"></canvas>
</div>
```

##### JavaScript

```html

<script type="module">
    import init, {start} from "./fosr_gui.js";

    async function run() {
        await init();
        await start("fosr_gui_canvas");
    }

    run();
</script>
```

#### Step 4: Serve with an HTTP server

Here is an example using `http-server`:

```shell
# Install http-server
npm install -g http-server

# Serve from project root
http-server ./public -p 8080
```

#### Shell script

Use the `build-web.sh` script to automate the build and serve process (requires `http-server` and a pre-built
`public/index.html`).

#### Generating `index.html`

The `public/index.html` file is not versioned and must be generated from markdown sources using pandoc:

```shell
# Install pandoc (if not already installed)

# Generate index.html
./public/generate-index-html.sh
```

Note: This script generates a simplified version without the dynamic help output from the `fosr` binary.
For the full version, see the `pages` job in `.gitlab-ci.yml`.
