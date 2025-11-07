use crate::structs::*;
use indicatif::{ProgressBar, ProgressState, ProgressStyle};
use pcap_file::pcap::{PcapPacket, PcapWriter};
use std::fmt::Write;
use std::fs::OpenOptions;
use std::io::BufWriter;

// pub struct PacketIterator {
//     reader: PcapReader<BufReader<File>>,
// }

// impl Iterator for PacketIterator {
//     type Item = Packet;

//     fn next(&mut self) -> Option<Self::Item> {
//         self.reader
//             .next_packet()
//             .map(|result| result.unwrap().into())
//     }
// }

// pub fn export_into_temporary(packets: &mut Vec<Packet>) -> PacketIterator {
//     // let mut packets: Vec<Packet> = packets.into_iter().flat_map(|p| p.packets).collect();
//     // log::warn!("Export!");
//     packets.sort_unstable();
//     let mut file = tempfile().unwrap();
//     let mut pcap_writer = PcapWriter::new(BufWriter::new(file)).expect("Error writing file");

//     for packet in packets.iter() {
//         pcap_writer
//             .write_packet(&PcapPacket::new(
//                 packet.timestamp,
//                 packet.data.len() as u32,
//                 &packet.data,
//             ))
//             .unwrap();
//     }
//     packets.clear();

//     let mut file = pcap_writer.into_writer().into_inner().unwrap();
//     file.seek(SeekFrom::Start(0)).unwrap();
//     let reader = PcapReader::new(BufReader::new(
//         file
//     ))
//     .unwrap();
//     PacketIterator { reader }
// }

// pub fn run_export_from_temporary(packets: Vec<PacketIterator>, outfile: String) -> usize {
//     log::trace!("Start pcap export thread");
//     let file_out = OpenOptions::new()
//         .write(true)
//         .create(true)
//         .truncate(true)
//         .open(&outfile)
//         .expect("Error opening or creating file");
//     let mut pcap_writer = PcapWriter::new(BufWriter::new(file_out)).expect("Error writing file");
//     log::trace!("Saving into {}", &outfile);

//     let mut total_size = 0;
//     for packet in kmerge(packets) {
//         let len = packet.data.len();
//         total_size += len;
//         pcap_writer
//             .write_packet(&PcapPacket::new(
//                 packet.timestamp,
//                 packet.data.len() as u32,
//                 &packet.data,
//             ))
//             .unwrap();
//     }
//     total_size
// }

/// Export the packets into a pcap file
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
