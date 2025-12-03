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
    cmd.arg("create-pcap")
        .args(["-o", &file_path])
        .args(["-s", "0"])
        .args(["-d", "1min"])
        .args(["-t", "0"])
        .args(["-p", "fast"])
        .args(["--tz", "CET"])
        .args(["-c", "tests/test_config.yaml"])
        .env("RUST_LOG", "trace")
        .spawn()?;
    cmd.assert().success();
    thread::sleep(time::Duration::from_millis(500));

    let mut file = File::open(&file_path)?;
    let mut sha256 = Sha256::new();
    io::copy(&mut file, &mut sha256)?;
    let hash = sha256.finalize();
    assert_eq!(
        hex::encode(hash),
        "131529091e2b4330dbc24f65c85b04657587cd6258ed1b1320516a27b54c60b4"
    );
    Ok(())
}

#[test]
fn deterministic_efficient_generation() -> Result<(), Box<dyn std::error::Error>> {
    let file_path = "deterministic-test.pcap";

    let mut cmd = Command::cargo_bin(pkg_name!())?;

    // ensure the generation is deterministic
    cmd.arg("create-pcap")
        .args(["-o", &file_path])
        .args(["-s", "0"])
        .args(["-d", "1min"])
        .args(["-t", "0"])
        .args(["-p", "efficient"])
        .args(["--tz", "CET"])
        .args(["-c", "tests/test_config.yaml"])
        .env("RUST_LOG", "trace")
        .spawn()?;
    cmd.assert().success();
    thread::sleep(time::Duration::from_millis(500));

    let mut file = File::open(&file_path)?;
    let mut sha256 = Sha256::new();
    io::copy(&mut file, &mut sha256)?;
    let hash = sha256.finalize();
    assert_eq!(
        hex::encode(hash),
        "131529091e2b4330dbc24f65c85b04657587cd6258ed1b1320516a27b54c60b4"
    );
    Ok(())
}
