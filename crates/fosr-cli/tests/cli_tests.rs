use assert_cmd::pkg_name;
use assert_cmd::prelude::*;
use sha2::Digest;
use sha2::Sha256;
use std::fs;
use std::fs::File;
use std::io;
use std::process::Command;
use std::{thread, time};

#[test]
fn deterministic_fast_generation() -> Result<(), Box<dyn std::error::Error>> {
    let file_path = "deterministic-test.pcap";

    let mut cmd = Command::cargo_bin(pkg_name!())?;

    // ensure the generation is deterministic
    cmd.arg("augment-dataset")
        .args(["-o", &file_path])
        .args(["-s", "0"])
        .args(["-d", "1h"])
        .args(["-t", "0"])
        .args(["-p", "fast"])
        .args(["--tz", "CET"])
        .args(["-m", "cupid"])
        .env("RUST_LOG", "trace")
        .spawn()?;
    cmd.assert().success();
    thread::sleep(time::Duration::from_millis(500));

    let hash = Sha256::digest(&fs::read_to_string(&file_path)?);
    assert_eq!(
        hex::encode(hash),
        "633e1a7cc866c23778f6fa3ef6d5501c5cb4e0007409a937dc62ec821caa5626"
    );
    Ok(())
}

#[test]
fn deterministic_efficient_generation() -> Result<(), Box<dyn std::error::Error>> {
    let file_path = "deterministic-test.pcap";

    let mut cmd = Command::cargo_bin(pkg_name!())?;

    // ensure the generation is deterministic
    cmd.arg("augment-dataset")
        .args(["-o", &file_path])
        .args(["-s", "0"])
        .args(["-d", "1h"])
        .args(["-t", "0"])
        .args(["-p", "fast"])
        .args(["--tz", "CET"])
        .args(["-m", "cupid"])
        .env("RUST_LOG", "trace")
        .spawn()?;
    cmd.assert().success();
    thread::sleep(time::Duration::from_millis(500));

    let hash = Sha256::digest(&fs::read_to_string(&file_path)?);
    assert_eq!(
        hex::encode(hash),
        "633e1a7cc866c23778f6fa3ef6d5501c5cb4e0007409a937dc62ec821caa5626"
    );
    Ok(())
}
