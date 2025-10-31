use assert_cmd::prelude::*;
use hex_literal::hex;
use sha2::Digest;
use sha2::Sha256;
use std::fs;
use std::fs::File;
use std::io;
use std::process::Command;

#[test]
fn deterministic_generation() -> Result<(), Box<dyn std::error::Error>> {
    let file_path = "deterministic-test.pcap";

    let mut cmd = Command::cargo_bin("fosr")?;

    // ensure the generation is deterministic
    cmd.arg("create-pcap")
        .args(["-o", &file_path])
        .args(["-s", "0"])
        .args(["-d", "1min"])
        .args(["-t", "0"])
        .arg("--order-pcap")
        .env("RUST_LOG", "trace")
        .spawn()?;
    cmd.assert().success();

    let mut file = File::open(&file_path)?;
    let mut sha256 = Sha256::new();
    io::copy(&mut file, &mut sha256)?;
    let hash = sha256.finalize();
    assert_eq!(
        hash[..],
        hex!("98a61cf7d0743ff30d8ae086b51c706b8b13a1c0dc18d3bd5d8479391ba952ce")
    );
    Ok(())
}

#[test]
fn deterministic_generation_monothread() -> Result<(), Box<dyn std::error::Error>> {
    let file_path = "deterministic-test.pcap";

    let mut cmd = Command::cargo_bin("fosr")?;

    // ensure the generation is deterministic
    cmd.arg("create-pcap")
        .args(["-o", &file_path])
        .args(["-s", "0"])
        .args(["-d", "1min"])
        .args(["-t", "0"])
        .arg("--order-pcap")
        .arg("--monothread")
        .env("RUST_LOG", "trace")
        .spawn()?;
    cmd.assert().success();

    let mut file = File::open(&file_path)?;
    let mut sha256 = Sha256::new();
    io::copy(&mut file, &mut sha256)?;
    let hash = sha256.finalize();
    assert_eq!(
        hash[..],
        hex!("98a61cf7d0743ff30d8ae086b51c706b8b13a1c0dc18d3bd5d8479391ba952ce")
    );
    Ok(())
}
