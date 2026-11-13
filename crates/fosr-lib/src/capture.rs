use std::{
    fs::File,
    io::{BufReader, BufWriter, Read},
    process::{Child, Command, Stdio},
    thread,
    time::Duration,
};

use itertools::kmerge;
use nix::{
    sys::signal::{Signal, kill},
    unistd::Pid,
};
use pcap_file::pcap::{PcapPacket, PcapReader, PcapWriter};

use crate::{
    Packet,
    netns::{ROUTER_NS, spawn_in},
    network::Network,
};

/// Capture of the traffic going through the router, with one tcpdump per port
pub struct RouterCapture {
    outfile: String,
    /// tcpdump processes and their temporary files
    captures: Vec<(Child, String)>,
}

impl RouterCapture {
    /// Start capturing on every port of the router
    pub fn start(topology: &Network, outfile: String) -> Result<Self, String> {
        let mut capture = RouterCapture {
            outfile,
            captures: Vec::new(),
        };
        for port in topology.capture_ports() {
            let file = format!("{}.{port}", capture.outfile);
            // -Q in: each packet once. -U: write packets right away. -Z root: keep the right to write
            let mut cmd = Command::new("tcpdump");
            cmd.args([
                "-Q", "in", "-U", "-n", "-Z", "root", "-i", &port, "-w", &file,
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null());
            let child = spawn_in(ROUTER_NS, &mut cmd)?;
            capture.captures.push((child, file));
        }
        // let tcpdump start before the traffic
        thread::sleep(Duration::from_secs(1));
        Ok(capture)
    }

    /// Stop the captures and merge them into the output file
    pub fn stop(mut self) -> Result<(), String> {
        let files = self.interrupt();
        merge_pcaps(&files, &self.outfile)?;
        for file in &files {
            let _ = std::fs::remove_file(file);
        }
        Ok(())
    }

    /// Stop every tcpdump with SIGINT, so they flush their file, and return their files
    fn interrupt(&mut self) -> Vec<String> {
        let mut files = Vec::new();
        for (mut child, file) in self.captures.drain(..) {
            let _ = kill(Pid::from_raw(child.id() as i32), Signal::SIGINT);
            let _ = child.wait();
            files.push(file);
        }
        files
    }
}

impl Drop for RouterCapture {
    /// On error, don't leave tcpdump running nor its files
    fn drop(&mut self) {
        for file in self.interrupt() {
            let _ = std::fs::remove_file(file);
        }
    }
}

/// Merge pcap files into one, sorted by time, keeping only one packet per file in memory
fn merge_pcaps(files: &[String], outfile: &str) -> Result<(), String> {
    let mut readers = Vec::new();
    for file in files {
        let f = File::open(file).map_err(|e| format!("{file}: {e}"))?;
        readers.push(PcapReader::new(BufReader::new(f)).map_err(|e| format!("{file}: {e}"))?);
    }
    let out = BufWriter::new(File::create(outfile).map_err(|e| format!("{outfile}: {e}"))?);
    let mut writer = PcapWriter::new(out).map_err(|e| e.to_string())?;

    // each file is already sorted by time, so a k-way merge is enough (like in run_fast)
    let files = readers
        .into_iter()
        .map(|mut r| std::iter::from_fn(move || next_packet(&mut r)));
    for packet in kmerge(files) {
        writer
            .write_packet(&PcapPacket::new(
                packet.timestamp,
                packet.data.len() as u32,
                &packet.data,
            ))
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Next packet of a pcap file (None at the end, or if the last packet was cut by tcpdump)
fn next_packet<R: Read>(reader: &mut PcapReader<R>) -> Option<Packet> {
    match reader.next_packet()? {
        Ok(p) => Some(Packet::from(p)),
        Err(e) => {
            log::warn!("Truncated capture: {e}");
            None
        }
    }
}
