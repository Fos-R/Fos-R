#![allow(unused)]

use crate::*;
use pcap::{Capture, PacketHeader};

pub fn write_pcap(file: &str, packets: Vec<Packet>) -> Result<(), pcap::Error>{
    let mut savefile = Capture::dead(pcap::Linktype(1))?.savefile("output.pcap")?;

    for packet in &packets {
        savefile.write(&pcap::Packet {
            header: &packet.header,
            data: &packet.data,
        });
    }

    Ok(())
}