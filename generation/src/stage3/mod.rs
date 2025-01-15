#![allow(unused)]

use crate::icmp::*;
use crate::tcp::*;
use crate::udp::*;
use crate::*;
use pcap::{Capture, PacketHeader};
use pnet_packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::{self, Ipv4Flags, MutableIpv4Packet};
use pnet_packet::tcp::{self, MutableTcpPacket, TcpFlags};
use rand::prelude::*;
use rand_pcg::Pcg32;

pub struct Stage3 {
    taint: bool,
} // In the future, add network/system configuration here

struct TcpPacketData {
    forward: u32,    // foward SEQ and backward ACK
    backward: u32,   // forward ACK and backward SEQ
    cwnd: usize,     // Congestion window size
    rwnd: usize,     // Receiver window size
    ssthresh: usize, // Slow start threshold
    mss: usize,      // Maximum Segment Size
}

impl TcpPacketData {
    fn new() -> Self {
        TcpPacketData {
            forward: random::<u32>(),
            backward: random::<u32>(),
            cwnd: 65535,     // Initial congestion window size (in bytes)
            rwnd: 65535,     // Receiver's advertised window size
            ssthresh: 65535, // Slow start threshold
            mss: 1460,       // Typical MSS
        }
    }
}

impl Stage3 {
    fn setup_ethernet_frame(&self, packet: &mut [u8]) -> Option<()> {
        let mut eth_packet = MutableEthernetPacket::new(packet)?;
        eth_packet.set_ethertype(EtherTypes::Ipv4);

        Some(())
    }

    fn setup_ip_packet(
        &self,
        packet: &mut [u8],
        flow: &FlowData,
        packet_info: &TCPPacketInfo,
    ) -> Option<()> {
        let len = packet.len();
        let mut ipv4_packet = MutableIpv4Packet::new(packet)?;

        // Generic fields of the IPv4 Packet
        ipv4_packet.set_version(4);
        ipv4_packet.set_header_length(5); // TODO: Set the correct header length and options if needed
        ipv4_packet.set_total_length(len as u16);
        ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);

        // Fields that depend on the direction
        match packet_info.get_direction() {
            PacketDirection::Forward => {
                ipv4_packet.set_ttl(flow.ttl_client);
                ipv4_packet.set_source(flow.src_ip);
                ipv4_packet.set_destination(flow.dst_ip);
            }
            PacketDirection::Backward => {
                ipv4_packet.set_ttl(flow.ttl_server);
                ipv4_packet.set_source(flow.dst_ip);
                ipv4_packet.set_destination(flow.src_ip);
            }
        }

        // Set the flags
        let ip_flags = if self.taint {
            0b100 + Ipv4Flags::DontFragment
        } else {
            Ipv4Flags::DontFragment
        };
        ipv4_packet.set_flags(ip_flags); // TODO: Set fragmentation based on the window size ??

        // Compute the checksum
        ipv4_packet.set_checksum(ipv4::checksum(&ipv4_packet.to_immutable()));

        Some(())
    }

    fn setup_tcp_packet(
        &self,
        rng: &mut Pcg32,
        packet: &mut [u8],
        flow: &FlowData,
        packet_info: &TCPPacketInfo,
        tcp_data: TcpPacketData, // Change to take ownership of tcp_data
    ) -> Option<TcpPacketData> {
        // Return TcpPacketData and an empty tuple
        let mut tcp_packet = MutableTcpPacket::new(packet)?;

        let mut new_tcp_data = tcp_data; // Create a new instance of TcpPacketData

        match packet_info.get_direction() {
            PacketDirection::Forward => {
                // Set the source and destination ports
                tcp_packet.set_source(flow.src_port);
                tcp_packet.set_destination(flow.dst_port);

                // Set sequence and acknowledgement numbers
                tcp_packet.set_sequence(new_tcp_data.forward);
                if packet_info.a_flag {
                    tcp_packet.set_acknowledgement(new_tcp_data.backward);
                }

                // Increment forward ACK and backward SEQ
                new_tcp_data.forward += packet_info.payload.get_payload_size() as u32;
            }
            PacketDirection::Backward => {
                // Set the source and destination ports
                tcp_packet.set_source(flow.dst_port);
                tcp_packet.set_destination(flow.src_port);

                // Set sequence and acknowledgement numbers
                tcp_packet.set_sequence(new_tcp_data.backward);
                if packet_info.a_flag {
                    tcp_packet.set_acknowledgement(new_tcp_data.forward);
                }

                new_tcp_data.backward += packet_info.payload.get_payload_size() as u32;
            }
        }

        // Set the payload
        match &packet_info.payload {
            Payload::Empty => (),
            Payload::Random(size) => {
                let mut payload = vec![0_u8;*size];
                rng.fill_bytes(&mut payload);
                tcp_packet.set_payload(payload.as_slice());
            }
            Payload::Replay(payload) => {
                tcp_packet.set_payload(payload);
            },
        }

        // Set the s | a | f | r | u | p flags
        tcp_packet.set_flags(
            (packet_info.s_flag as u8 * TcpFlags::SYN)
                | (packet_info.a_flag as u8 * TcpFlags::ACK)
                | (packet_info.f_flag as u8 * TcpFlags::FIN)
                | (packet_info.r_flag as u8 * TcpFlags::RST)
                | (packet_info.u_flag as u8 * TcpFlags::URG)
                | (packet_info.p_flag as u8 * TcpFlags::PSH),
        );

        // Simulate the congestion window
        let mut cwr_flag = false;
        if rand::random::<f32>() < 0.05 {
            // 5% chance of congestion
            new_tcp_data.ssthresh = new_tcp_data.cwnd / 2; // Halve the threshold
            new_tcp_data.cwnd = new_tcp_data.ssthresh; // Enter congestion avoidance
            cwr_flag = true; // Indicate CWR flag should be set
        } else if new_tcp_data.cwnd < new_tcp_data.ssthresh {
            // Slow start: Exponential increase
            new_tcp_data.cwnd += new_tcp_data.mss;
        } else {
            // Congestion avoidance: Linear increase
            new_tcp_data.cwnd += (new_tcp_data.mss * new_tcp_data.mss) / new_tcp_data.cwnd;
        }

        // Set the window size
        let effective_window = new_tcp_data.cwnd.min(new_tcp_data.rwnd) as u16;
        tcp_packet.set_window(effective_window); // TODO: Compute the correct window size

        // Set the CWR flag if congestion occurred
        if cwr_flag {
            tcp_packet.set_flags(tcp_packet.get_flags() | TcpFlags::CWR);
        }

        // Set the data offset
        tcp_packet.set_data_offset(5); // TODO: Are there any options?

        // Compute the checksum
        tcp_packet.set_checksum(tcp::ipv4_checksum(
            &tcp_packet.to_immutable(),
            match packet_info.get_direction() {
                PacketDirection::Forward => &flow.src_ip,
                PacketDirection::Backward => &flow.dst_ip,
            },
            match packet_info.get_direction() {
                PacketDirection::Forward => &flow.dst_ip,
                PacketDirection::Backward => &flow.src_ip,
            },
        ));

        Some(new_tcp_data) // Return the new tcp_data and an empty tuple
    }

    fn get_pcap_header(&self, packet_size: usize, ts: Duration) -> PacketHeader {
        PacketHeader {
            ts: self.instant_to_timeval(ts),
            caplen: packet_size as u32,
            len: packet_size as u32,
        }
    }

    fn instant_to_timeval(&self, duration: Duration) -> libc::timeval {
        libc::timeval {
            tv_sec: duration.as_secs() as _,
            tv_usec: duration.subsec_micros() as _,
        }
    }

    pub fn new(taint: bool) -> Self {
        Stage3 { taint }
    }

    /// Generate TCP packets from an intermediate representation
    pub fn generate_tcp_packets(&self, input: SeededData<PacketsIR<TCPPacketInfo>>) -> SeededData<Packets> {
        let mut rng = Pcg32::seed_from_u64(input.seed);
        let ip_start = MutableEthernetPacket::minimum_packet_size();
        let tcp_start = ip_start + MutableIpv4Packet::minimum_packet_size();
        let flow = match &input.data.flow {
            Flow::TCP(f) => f,
            Flow::UDP(f) => f,
            Flow::ICMP(f) => f,
        };
        let mut tcp_data = TcpPacketData::new();
        let mut packets: Vec<Packet> = Vec::new();

        for packet_info in &input.data.packets_info {
            let packet_size = MutableEthernetPacket::minimum_packet_size()
                + MutableIpv4Packet::minimum_packet_size()
                + MutableTcpPacket::minimum_packet_size()
                + packet_info.payload.get_payload_size();

            let mut packet = vec![0u8; packet_size];

            self.setup_ethernet_frame(&mut packet[..]).expect("Incorrect Ethernet frame");
            self.setup_ip_packet(&mut packet[ip_start..], flow, packet_info).expect("Incorrect IP packet");
            tcp_data =
                self.setup_tcp_packet(&mut rng, &mut packet[tcp_start..], flow, packet_info, tcp_data).expect("Incorrect TCP packet");

            packets.push(Packet {
                header: self
                    .get_pcap_header(packet_size, packet_info.get_ts()),
                data: packet.clone(),
            });
        }

        SeededData { seed: rng.next_u64(), data: Packets { packets, flow: input.data.flow } }
    }

    /// Generate UDP packets from an intermediate representation
    pub fn generate_udp_packets(&self, input: SeededData<PacketsIR<UDPPacketInfo>>) -> SeededData<Packets> {
        let mut rng = Pcg32::seed_from_u64(input.seed);
        todo!()
    }

    /// Generate ICMP packets from an intermediate representation
    pub fn generate_icmp_packets(&self, input: SeededData<PacketsIR<ICMPPacketInfo>>) -> SeededData<Packets> {
        let mut rng = Pcg32::seed_from_u64(input.seed);
        todo!()
    }
}

pub fn insert_noise(data: &mut SeededData<Packets>) {
    todo!()
}

pub fn pcap_export(mut data: Vec<Packet>, outfile: &str, append: bool)  -> Result<(), pcap::Error> {
    let mut capture = Capture::dead(pcap::Linktype(1))?;
    let mut savefile = if append { capture.savefile_append(outfile)? } else { capture.savefile(outfile)? };
    log::info!("Saving into {}", outfile);
    data.sort();
    for packet in data {
        savefile.write(&pcap::Packet {
            header: &packet.header,
            data: &packet.data,
        });
    }

    Ok(())
}


