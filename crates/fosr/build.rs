#[cfg(all(any(target_os = "windows", target_os = "linux"), feature = "ebpf"))]
use anyhow::{Context as _, anyhow};
#[cfg(all(any(target_os = "windows", target_os = "linux"), feature = "ebpf"))]
use aya_build::cargo_metadata;

#[cfg(all(any(target_os = "windows", target_os = "linux"), feature = "ebpf"))]
fn main() -> anyhow::Result<()> {
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

#[cfg(not(all(any(target_os = "windows", target_os = "linux"), feature = "ebpf")))]
fn main() {}
