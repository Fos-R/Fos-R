## Compile from source

You can also compile Fos-R from source directly. Fos-R is distributed with [crates.io](https://crates.io/crates/fosr). First, install Rust with [rustup](https://rustup.rs/). Then, you can install the stable version of Fos-R with:

`cargo install fosr`

Alternatively, you can install the experimental version with:

`cargo install --git https://gitlab.inria.fr/pirat-public/Fos-R.git fosr`

You can check the installation with:

`fosr`

The sources of Fos-R are located on [Inria’s GitLab](https://gitlab.inria.fr/pirat-public/Fos-R). There is also a [GitHub mirror](https://github.com/Fos-R/Fos-R).

## Use as a library

Fos-R also includes a Rust library that exposes the main parts of the software. Its documentation is [here](doc/fosr/all.html). You can add the stable version of Fos-R to a Rust project with `cargo add fosr` and the experimental version with `cargo add --git https://gitlab.inria.fr/pirat-public/Fos-R.git fosr`.
