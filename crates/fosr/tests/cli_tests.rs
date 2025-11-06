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
        "98a61cf7d0743ff30d8ae086b51c706b8b13a1c0dc18d3bd5d8479391ba952ce"
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
        "98a61cf7d0743ff30d8ae086b51c706b8b13a1c0dc18d3bd5d8479391ba952ce"
    );
    Ok(())
}
