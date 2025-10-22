
| Target                  | Net injection | Iptables      | eBPF          | Binary file                                           | .deb package                                  |
| :---------------------: | :-----------: | :-----------: | :-----------: | :----------:                                          | :-----------:                                 |
| Linux x86 (32 bits)     |               |               |               | [link](bin/i686-unknown-linux-gnu/release/fosr)       | [link](bin/debian/fosr_0.1.2-dev-1_i386.deb)  |
| Linux x86 (64 bits)     | &check;       |               | &check;       | [link](bin/x86_64-unknown-linux-gnu/release/fosr)     | [link](bin/debian/fosr_0.1.2-dev-1_amd64.deb) |
| Linux ARM (32 bits)     | &check;       |               | &check;       | [link](bin/arm-unknown-linux-musleabihf/release/fosr) | [link](bin/debian/fosr_0.1.2-dev-1_armhf.deb) |
| Linux ARM (64 bits)     | &check;       |               | &check;       | [link](bin/aarch64-unknown-linux-gnu/release/fosr)    | [link](bin/debian/fosr_0.1.2-dev-1_arm64.deb) |

## Compile from source

You can also compile Fos-R from source directly. Fos-R is distributed with [crates.io](https://crates.io/crates/fosr). First, install Rust with [rustup](https://rustup.rs/). If you want to `ebpf` features (cf. below), you will need to install a few more dependencies:

`rustup toolchain install nightly --component rust-src`

`cargo install bpf-linker`

Then, you can install the stable version of Fos-R with:

`cargo install fosr`

Alternatively, you can install the experimental version with:

`cargo install --git https://gitlab.inria.fr/pirat-public/Fos-R.git fosr`

You can check the installation with `fosr`.

The sources of Fos-R are located on [Inria’s GitLab](https://gitlab.inria.fr/pirat-public/Fos-R). There is also a [GitHub mirror](https://github.com/Fos-R/Fos-R).

## Use as a library

Fos-R also includes a Rust library that exposes the main parts of the software. Its documentation is [here](doc/fosr/all.html). You can add the stable version of Fos-R to a Rust project with:

`cargo add fosr`

For the experimental version:

`cargo add --git https://gitlab.inria.fr/pirat-public/Fos-R.git fosr`.


