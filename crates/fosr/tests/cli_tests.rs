use assert_cmd::prelude::*;
use sha2::Digest;
use sha2::Sha256;
use std::fs::File;
use std::io;
use std::process::Command;
use hex_literal::hex;
use tempfile::tempdir;

#[test]
fn deterministic_generation() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let file_path = dir.path().join("out.pcap");

    let mut cmd = Command::cargo_bin("fosr")?;

    // ensure the generation is deterministic
    cmd.arg("create-pcap")
        .arg("-o")
        .arg("out.pcap")
        .arg("-s")
        .arg("0")
        .arg("-d")
        .arg("1h")
        .arg("--order-pcap")
        .arg("-t")
        .arg("0");
    cmd.assert().success();

    let mut file = File::open("out.pcap")?;
    let mut sha256 = Sha256::new();
    io::copy(&mut file, &mut sha256)?;
    let hash = sha256.finalize();
    Ok(assert_eq!(hash[..], hex!("8b4c7599bc223c2e4705a20e5d47f1c5fe357d773dd25a19b6a27281db163cb8")))
}
