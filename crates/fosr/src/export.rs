use crate::structs::*;
use std::fs::OpenOptions;
use pcap_file::pcap::{PcapWriter, PcapPacket};
use std::io::BufWriter;
use indicatif::{ProgressBar, ProgressStyle, ProgressState};
use std::fmt::Write;

/// Runs the pcap export thread.
///
/// The packets are sorted by their header (timestamp), and then written
/// sequentially to the specified file. If append is true, the packets are
/// appended to an existing pcap file; otherwise, a new file is created.
pub fn run_export(
    rx_pcap: thingbuf::mpsc::blocking::Receiver<Packets, PacketsRecycler>,
    outfile: String,
    order_pcap: bool,
) {
    log::trace!("Start pcap export thread");
    let file_out = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&outfile)
        .expect("Error opening or creating file");
    let mut pcap_writer = PcapWriter::new(BufWriter::new(file_out)).expect("Error writing file");
    log::trace!("Saving into {}", &outfile);

    if order_pcap {
        let mut all_packets: Vec<Packet> = vec![];
        while let Some(packets) = rx_pcap.recv_ref() {
            for packet in packets.packets.iter() {
                all_packets.push(packet.clone());
            }
        }

        log::info!("Sorting the packets");
        all_packets.sort_unstable();

        let pb_pcap = ProgressBar::new(all_packets.len() as u64);
        pb_pcap.set_style(
            ProgressStyle::with_template("{spinner:.green} PCAP export [{wide_bar}] ({eta})")
                .unwrap()
                .with_key("eta", |state: &ProgressState, w: &mut dyn Write| {
                    write!(w, "{:.1}s", state.eta().as_secs_f64()).unwrap()
                }),
        );

        for packet in all_packets.iter() {
            pb_pcap.inc(1);
            pcap_writer
                .write_packet(&PcapPacket::new(
                    packet.timestamp,
                    packet.data.len() as u32,
                    &packet.data,
                ))
                .unwrap();
        }
        pb_pcap.finish();
    } else {
        // write them as they come
        while let Some(packets) = rx_pcap.recv_ref() {
            for packet in packets.packets.iter() {
                pcap_writer
                    .write_packet(&PcapPacket::new(
                        packet.timestamp,
                        packet.data.len() as u32,
                        &packet.data,
                    ))
                    .unwrap();
            }
        }
    }
}

/// Simulates a pcap export. It must be called to consume the generated data.
pub fn run_dummy_export(rx_pcap: thingbuf::mpsc::blocking::Receiver<Packets, PacketsRecycler>) {
    while rx_pcap.recv_ref().is_some() {}
}
