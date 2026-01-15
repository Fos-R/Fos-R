---
title: "Fos-R, the synthetic network traffic generator"
author: "Pierre-François Gimenez"
description: "A network synthetic traffic generator"
---

![](logo.png)

<center>
<img style="width: auto" src="https://img.shields.io/badge/Rust-blue?logo=rust"> <!-- language -->
<img style="width: auto" src="https://img.shields.io/crates/v/fosr.svg?color=brightgreen"> <!-- version -->
<img style="width: auto" src="https://img.shields.io/crates/d/fosr?label=downloads%20%28crates.io%29"> <!-- downloads -->
<img style="width: auto" src="https://img.shields.io/crates/l/fosr"><!-- license -->
<img style="width: auto" src="https://gitlab.inria.fr/pirat-public/Fos-R/badges/main/pipeline.svg"> <!-- CI status -->
<img style="width: auto" src="https://img.shields.io/gitlab/last-commit/pirat-public%2FFos-R?gitlab_url=https%3A%2F%2Fgitlab.inria.fr%2F"> <!-- last commit -->
</center>

Fos-R is a high-quality and high-throughput network traffic generator based on AI models. Fos-R can be used for:

- creating in a few minutes network datasets lasting for weeks, for example to learn AI models or to evaluate intrusion detection systems;
- generating background traffic in cyber ranges so the exercise is more realistic and attacks are more difficult to detect;
- generating background traffic in low- or high-interactivity honeypots to deceive attackers.

# Try it online!

<!-- Start of WASM GUI Integration -->
<div id="gui_wrapper">
<div id="gui_loading_text">Loading Application...</div>
<canvas class="gui_canvas" id="fosr_gui_canvas"></canvas>
</div>
<script type="module">
    // Import the WASM initializer and start function.
    import init, { start } from './fosr_gui.js';

    async function run() {
        // 1. Initialize the WASM module
        await init();

        // 2. Start the application, passing the canvas ID
        await start('fosr_gui_canvas');

        // 3. Remove the loading text once initialization is complete
        const loadingText = document.getElementById('gui_loading_text');
        if (loadingText) {
            loadingText.remove();
        }
    }

    run().catch(error => {
        console.error('Failed to start WASM application:', error);
        // Update the loading text to show an error message
        const loadingText = document.getElementById('gui_loading_text');
        if (loadingText) {
            loadingText.innerHTML = '<p style="color: red;">Application failed to load. Check console for details.</p>';
        }
    });
</script>
<!-- End of WASM GUI Integration -->

**The online version has limited performance and features. Download Fos-R for the full experience!**

# Get Fos-R

The sources are available on the [GitLab repository](https://gitlab.inria.fr/pirat-public/Fos-R) or the [GitHub mirror](https://github.com/Fos-R/Fos-R).

## Cargo features

Fos-R make use of Cargo features for conditional compilation. The available features:

- `iptables`: a method for network injection (Linux only)
- `ebpf`: a method for network injection (Windows and Linux) [default]

If you do not enable `iptables` or `ebpf`, Fos-R won’t be able to inject traffic on the network. Generation is always available.

## Stable binaries

The binaries of the last stable versions are stored on [GitHub](https://github.com/Fos-R/Fos-R/releases).

## Experimental binaries
