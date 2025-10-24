A small eBPF program used by [Fos-R](https://crates.io/crates/fosr).

## Description

The eBPF program verifies the "taint bit" added by Fos-R on all generated network communications to make sure that they don't interfere with the operating system network stack (e.g., rejecting some packets since the destination port is not open).

## Usage

This crate should be used as a (library) dependency since it will trigger on each build of the library the build of the eBPF program. The latter will then be embedded as aligned bytes into the library, and exported into a static const global variable `EBPF_PROGRAM`. You can then use `aya` to load it and use it in your program:
```rust
use aya::programs::{Xdp, XdpFlags};

let mut ebpf = aya::Ebpf::load(fosr_ebpf::EBPF_PROGRAM).expect("Couldn't retrieve eBPF program");
let program: &mut Xdp = ebpf
    .program_mut("fosr_ebpf")
    .expect("Failed to get mut reference of program")
    .try_into()
    .expect("Failed to get Xdp program reference");
program.load().expect("Failed to load eBPF program");
```

Please note that you need the `bpf-linker` dependency to build the eBPF program (and therefore use this crate):
```
cargo install bpf-linker
```

