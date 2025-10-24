use anyhow::{Context as _, anyhow};
use aya_build::cargo_metadata;
use which::which;

/// Building this crate has an undeclared dependency on the `bpf-linker` binary. This would be
/// better expressed by [artifact-dependencies][bindeps] but issues such as
/// https://github.com/rust-lang/cargo/issues/12385 make their use impractical for the time being.
///
/// This file implements an imperfect solution: it causes cargo to rebuild the crate whenever the
/// mtime of `which bpf-linker` changes. Note that possibility that a new bpf-linker is added to
/// $PATH ahead of the one used as the cache key still exists. Solving this in the general case
/// would require rebuild-if-changed-env=PATH *and* rebuild-if-changed={every-directory-in-PATH}
/// which would likely mean far too much cache invalidation.
///
/// [bindeps]: https://doc.rust-lang.org/nightly/cargo/reference/unstable.html?highlight=feature#artifact-dependencies
fn main() -> anyhow::Result<()> {
    let bpf_linker = which("bpf-linker").unwrap();
    println!("cargo:rerun-if-changed={}", bpf_linker.to_str().unwrap());

    // We try to avoid recursion here, since build_ebpf will still
    let target = std::env::var_os("TARGET");
    if let Some(target) = target
        && (target == "bpfeb-unknown-none" || target == "bpfel-unknown-none")
    {
        return Ok(());
    }

    // On build trigger, let's build our ebpf binary
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name == "fosr-ebpf")
        .ok_or_else(|| anyhow!("fosr-ebpf package not found"))?;
    aya_build::build_ebpf([ebpf_package])
}
