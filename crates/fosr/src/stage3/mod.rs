use crate::config::Hosts;
use crate::icmp::*;
use crate::structs::*;
use crate::tcp::TCPPacketInfo;
use crate::udp::*;
use crate::ui::Stats;

use crossbeam_channel::{Receiver, Sender};
use indicatif::{ProgressBar, ProgressState, ProgressStyle};
use pcap_file::pcap::PcapPacket;
use pcap_file::pcap::PcapWriter;
use pnet::util::MacAddr;
use pnet_packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet_packet::ip::IpNextHeaderProtocol;
use pnet_packet::ipv4::{self, MutableIpv4Packet};
use pnet_packet::tcp::{self, MutableTcpPacket, TcpFlags};
use pnet_packet::udp::MutableUdpPacket;
use rand_core::*;
use rand_pcg::Pcg32;
use std::fmt::Write;
use std::fs::OpenOptions;
use std::io::BufWriter;
use std::net::Ipv4Addr;
use std::num::Wrapping;
use std::sync::Arc;

/// Represents stage 3 of the packet generator.
/// It contains configuration data and state necessary for generating packets.
#[derive(Debug, Clone)]
pub struct Stage3 {
    taint: bool,
    config: Hosts,
    zero: MacAddr,
}

struct TcpPacketData {
    forward: Wrapping<u32>,  // forward SEQ and backward ACK
    backward: Wrapping<u32>, // forward ACK and backward SEQ
    cwnd: usize,             // Congestion window size
    rwnd: usize,             // Receiver window size
    ssthresh: usize,         // Slow start threshold
    mss: usize,              // Maximum Segment Size
}

impl TcpPacketData {
    /// Creates new TCP packet data with randomized initial sequence numbers.
    fn new(rng: &mut impl RngCore) -> Self {
        TcpPacketData {
            forward: Wrapping(rng.next_u32()),
            backward: Wrapping(rng.next_u32()),
            cwnd: 65535,     // Initial congestion window size (in bytes)
            rwnd: 65535,     // Receiver's advertised window size
            ssthresh: 65535, // Slow start threshold
            mss: 1460,       // Typical MSS
        }
    }
}

impl Stage3 {
    /// Configures the Ethernet frame by setting the source, destination MAC addresses,
    /// and setting the EtherType to IPv4.
    fn setup_ethernet_frame(
        &self,
        packet: &mut [u8],
        src_mac: &MacAddr,
        dst_mac: &MacAddr,
    ) -> Option<()> {
        let mut eth_packet = MutableEthernetPacket::new(packet)?;
        eth_packet.set_ethertype(EtherTypes::Ipv4);
        eth_packet.set_source(*src_mac);
        eth_packet.set_destination(*dst_mac);

        Some(())
    }

    /// Sets up the IPv4 packet inside a given buffer.
    /// It assigns generic fields (version, header_length, total_length, protocol, identification)
    /// and adjusts source, destination, and TTL based on the packet direction;
    /// then calculates and sets the IPv4 header checksum.
    fn setup_ip_packet<P: PacketInfo>(
        &self,
        rng: &mut impl RngCore,
        packet: &mut [u8],
        flow: &Flow,
        packet_info: &P,
    ) -> Option<()> {
        let len = packet.len();
        let mut ipv4_packet = MutableIpv4Packet::new(packet)?;

        // Generic fields of the IPv4 Packet
        ipv4_packet.set_version(4);
        ipv4_packet.set_header_length(5); // TODO: Set the correct header length and options if needed
        ipv4_packet.set_total_length(len as u16);
        ipv4_packet.set_next_level_protocol(IpNextHeaderProtocol::new(
            flow.get_proto().get_protocol_number(),
        ));
        ipv4_packet.set_identification(rng.next_u32() as u16);
        let flow = flow.get_data();

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
        let ip_flags = if self.taint { 0b100 } else { 0 };
        ipv4_packet.set_flags(ip_flags); // TODO: Set fragmentation based on the window size ??

        // Compute the checksum
        ipv4_packet.set_checksum(ipv4::checksum(&ipv4_packet.to_immutable()));

        Some(())
    }

    /// Configures the TCP packet within a given buffer.
    ///
    /// It sets the source/destination ports, sequence/ACK numbers, TCP flags, window size,
    /// and simulates congestion behavior (including CWR flag if needed). Finally,
    /// it computes and sets the TCP checksum.
    ///
    /// Returns an updated TcpPacketData structure for further packet generation.
    fn setup_tcp_packet(
        &self,
        rng: &mut impl RngCore,
        packet: &mut [u8],
        flow: &FlowData,
        packet_info: &TCPPacketInfo,
        tcp_data: TcpPacketData, // Change to take ownership of tcp_data
        payload_array: &mut [u8; 65536],
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
                tcp_packet.set_sequence(new_tcp_data.forward.0);
                if packet_info.a_flag {
                    tcp_packet.set_acknowledgement(new_tcp_data.backward.0);
                }

                // Increment forward ACK and backward SEQ
                if packet_info.s_flag {
                    new_tcp_data.forward += 1;
                } else {
                    new_tcp_data.forward += packet_info.payload.get_payload_size() as u32;
                }
            }
            PacketDirection::Backward => {
                // Set the source and destination ports
                tcp_packet.set_source(flow.dst_port);
                tcp_packet.set_destination(flow.src_port);

                // Set sequence and acknowledgement numbers
                tcp_packet.set_sequence(new_tcp_data.backward.0);
                if packet_info.a_flag {
                    tcp_packet.set_acknowledgement(new_tcp_data.forward.0);
                }

                if packet_info.s_flag {
                    new_tcp_data.backward += 1;
                } else {
                    new_tcp_data.backward += packet_info.payload.get_payload_size() as u32;
                }
            }
        }

        // Set the payload
        match &packet_info.payload {
            Payload::Empty => (),
            Payload::Random(size) => {
                rng.fill_bytes(&mut payload_array[0..*size]);
                tcp_packet.set_payload(&payload_array[0..*size]);
            }
            Payload::Replay(payload) => {
                tcp_packet.set_payload(payload);
            }
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
        if rng.next_u32() % 100 < 5 {
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

    /// Configures the UDP packet within a given buffer.
    ///
    /// It sets source/destination ports, assigns the payload (either random or replayed),
    /// adjusts the UDP length field, and computes/checks the UDP checksum.
    fn setup_udp_packet(
        &self,
        rng: &mut Pcg32,
        packet: &mut [u8],
        flow: &FlowData,
        packet_info: &UDPPacketInfo,
        payload_array: &mut [u8; 65536],
    ) -> Option<()> {
        let mut udp_packet = MutableUdpPacket::new(packet)?;

        // Set the source and destination ports
        match packet_info.get_direction() {
            PacketDirection::Forward => {
                udp_packet.set_source(flow.src_port);
                udp_packet.set_destination(flow.dst_port);
            }
            PacketDirection::Backward => {
                udp_packet.set_source(flow.dst_port);
                udp_packet.set_destination(flow.src_port);
            }
        }
        // Set the payload
        match &packet_info.payload {
            Payload::Empty => (),
            Payload::Random(size) => {
                rng.fill_bytes(&mut payload_array[0..*size]);
                udp_packet.set_payload(&payload_array[0..*size]);
                udp_packet.set_length((*size as u16) + 8);
            }
            Payload::Replay(payload) => {
                udp_packet.set_length((payload.len() as u16) + 8);
                udp_packet.set_payload(payload);
            }
        }
        // Compute the checksum
        udp_packet.set_checksum(pnet_packet::udp::ipv4_checksum(
            &udp_packet.to_immutable(),
            match packet_info.get_direction() {
                PacketDirection::Forward => &flow.src_ip,
                PacketDirection::Backward => &flow.dst_ip,
            },
            match packet_info.get_direction() {
                PacketDirection::Forward => &flow.dst_ip,
                PacketDirection::Backward => &flow.src_ip,
            },
        ));
        Some(())
    }

    pub fn new(taint: bool, config: Hosts) -> Self {
        Stage3 {
            taint,
            config,
            zero: MacAddr::zero(),
        }
    }

    /// Generates a sequence of TCP packets from an intermediate representation.
    ///
    /// For each packet info entry, it:
    ///   - Calculates the packet size.
    ///   - Configures the Ethernet, IPv4, and TCP layers.
    ///   - Updates TCP sequence numbers using TcpPacketData.
    ///   - Captures the packet timestamp and header.
    ///
    /// Returns a Packets struct encapsulating the packet data, directions, timestamps, and flow.
    pub fn generate_tcp_packets(
        &self,
        input: &SeededData<PacketsIR<TCPPacketInfo>>,
        packets: &mut Packets,
        payload_array: &mut [u8; 65536],
    ) {
        let mut rng = Pcg32::seed_from_u64(input.seed);
        let ip_start = MutableEthernetPacket::minimum_packet_size();
        let tcp_start = ip_start + MutableIpv4Packet::minimum_packet_size();
        let flow = &input.data.flow.get_data();
        let mut tcp_data = TcpPacketData::new(&mut rng);

        for packet_info in &input.data.packets_info {
            let packet_size = MutableEthernetPacket::minimum_packet_size()
                + MutableIpv4Packet::minimum_packet_size()
                + MutableTcpPacket::minimum_packet_size()
                + packet_info.payload.get_payload_size();

            let mut packet = vec![0u8; packet_size]; // pool ?

            let mut mac_src = self.config.get_mac(&flow.src_ip).unwrap_or(&self.zero);
            let mut mac_dst = self.config.get_mac(&flow.dst_ip).unwrap_or(&self.zero);
            if matches!(packet_info.get_direction(), PacketDirection::Backward) {
                (mac_src, mac_dst) = (mac_dst, mac_src);
            }
            self.setup_ethernet_frame(&mut packet[..], mac_src, mac_dst)
                .expect("Incorrect Ethernet frame");
            self.setup_ip_packet(
                &mut rng,
                &mut packet[ip_start..],
                &input.data.flow,
                packet_info,
            )
            .expect("Incorrect IP packet");
            tcp_data = self
                .setup_tcp_packet(
                    &mut rng,
                    &mut packet[tcp_start..],
                    flow,
                    packet_info,
                    tcp_data,
                    payload_array,
                )
                .expect("Incorrect TCP packet");

            packets.packets.push(Packet {
                timestamp: packet_info.get_ts(),
                data: packet,
            });
            packets.directions.push(packet_info.get_direction());
            packets.timestamps.push(packet_info.get_ts());
        }
    }

    /// Generates a sequence of UDP packets from an intermediate representation.
    ///
    /// For each packet info entry, it:
    ///   - Calculates the packet size.
    ///   - Configures the Ethernet, IPv4, and UDP layers.
    ///   - Captures the packet timestamp and header.
    ///
    /// Returns a Packets struct encapsulating the packet data, directions, timestamps, and flow.
    pub fn generate_udp_packets(
        &self,
        input: &SeededData<PacketsIR<UDPPacketInfo>>,
        packets: &mut Packets,
        payload_array: &mut [u8; 65536],
    ) {
        let mut rng = Pcg32::seed_from_u64(input.seed);
        let ip_start = MutableEthernetPacket::minimum_packet_size();
        let udp_start = ip_start + MutableIpv4Packet::minimum_packet_size();
        let flow = &input.data.flow.get_data();

        for packet_info in &input.data.packets_info {
            let packet_size = MutableEthernetPacket::minimum_packet_size()
                + MutableIpv4Packet::minimum_packet_size()
                + MutableUdpPacket::minimum_packet_size()
                + packet_info.payload.get_payload_size();

            let mut packet = vec![0u8; packet_size];

            self.setup_ethernet_frame(
                &mut packet[..],
                self.config.get_mac(&flow.src_ip).unwrap_or(&self.zero),
                self.config.get_mac(&flow.dst_ip).unwrap_or(&self.zero),
            )
            .expect("Incorrect Ethernet frame");
            self.setup_ip_packet(
                &mut rng,
                &mut packet[ip_start..],
                &input.data.flow,
                packet_info,
            )
            .expect("Incorrect IP packet");
            self.setup_udp_packet(
                &mut rng,
                &mut packet[udp_start..],
                flow,
                packet_info,
                payload_array,
            )
            .expect("Incorrect UDP packet");

            packets.packets.push(Packet {
                timestamp: packet_info.get_ts(),
                data: packet,
            });
            packets.directions.push(packet_info.get_direction());
            packets.timestamps.push(packet_info.get_ts());
        }
        packets.flow = input.data.flow;
    }

    /// Generate ICMP packets from an intermediate representation
    #[allow(unused)]
    pub fn generate_icmp_packets(
        &self,
        input: &SeededData<PacketsIR<ICMPPacketInfo>>,
        packets: &mut Packets,
        payload_array: &mut [u8; 65536],
    ) {
        // let mut rng = Pcg32::seed_from_u64(input.seed);
        todo!()
    }
}

// fn insert_noise(data: &mut SeededData<Packets>) {
//     todo!()
// }

/// Sends packets online based on the local interfaces.
///
/// Depending on whether the source, destination, or both IPs exist on local
/// interfaces, the function sends the packet flow to stage 4 (tx_s3) in one or
/// two forms. If both IPs are local, a clone is sent, and then the flow is
/// reversed before sending to ensure stage 4 is always the source.
pub fn send_online(
    local_interfaces: &[Ipv4Addr],
    mut flow_packets: Packets,
    tx_s3: &Sender<Packets>,
) {
    // check if exist
    let f = flow_packets.flow.get_data();
    let src_s4 = local_interfaces.contains(&f.src_ip);
    let dst_s4 = local_interfaces.contains(&f.dst_ip);
    if src_s4 && dst_s4 {
        // log::info!("Both source and destination IP are local");
        // only copy if we have to
        tx_s3.send(flow_packets.clone()).unwrap();
        // ensure stage 4 is always the source
        flow_packets.reverse();
        tx_s3.send(flow_packets).unwrap();
    } else if src_s4 {
        log::trace!("Source IP is local");
        tx_s3.send(flow_packets).unwrap();
    } else if dst_s4 {
        log::trace!("Destination IP is local");
        // ensure stage 4 is always the source
        flow_packets.reverse();
        tx_s3.send(flow_packets).unwrap();
    }
}

/// Sends a packet flow to the pcap pcap channel.
///
/// This function forwards the provided packet flow to the pcap, where it
/// may be further processed (for example, noise insertion) before export.
fn send_pcap(flow_packets: thingbuf::mpsc::blocking::SendRef<Packets>) {
    // if noise { // insert noise // TODO: find a better way to do it
    //     stage3::insert_noise(&mut noisy_flow);
    // }
    drop(flow_packets); // actually send (the drop in itself is useful but easier to read)
    // tx_s3_to_pcap.send(flow_packets).unwrap();
}

/// Runs stage 3 of the pipeline, processing incoming seeded packet representations.
///
/// This function receives intermediate packet data from rx_s3, generates complete
/// packets using the provided generator function, and then sends the generated flows
/// to appropriate channels based on the configuration (online transmission and/or pcap export).
pub fn run<T: PacketInfo>(
    generator: impl Fn(&SeededData<PacketsIR<T>>, &mut Packets, &mut [u8; 65536]),
    local_interfaces: Vec<Ipv4Addr>,
    rx_s3: Receiver<SeededData<PacketsIR<T>>>,
    tx_s3: Option<Sender<Packets>>,
    tx_s3_to_pcap: thingbuf::mpsc::blocking::Sender<Packets, PacketsRecycler>, // TODO: Option
    stats: Arc<Stats>,
    pcap_export: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Prepare stage 3
    log::trace!("Start S3");

    let mut payload_array: [u8; 65536] = [0; 65536]; // to avoid allocating Vec for payloads
    // everytime. 65536 is the maximum payload
    // size.
    for headers in rx_s3 {
        // log::trace!("Creating packets");
        let mut flow_packets = tx_s3_to_pcap.send_ref()?;
        // flow_packets.clear();
        generator(&headers, &mut flow_packets, &mut payload_array);
        flow_packets.flow = headers.data.flow;
        stats.increase(&flow_packets);

        // only copy the flows if we need to send it to online and pcap
        if let Some(ref tx_s3) = tx_s3 {
            send_online(&local_interfaces, flow_packets.clone(), tx_s3);
        }
        if pcap_export {
            send_pcap(flow_packets);
        }
        if stats.should_stop() {
            break;
        }
    }
    log::trace!("S3 stops");
    Ok(())
}

/// Runs the pcap export thread.
///
/// The packets are sorted by their header (timestamp), and then written
/// sequentially to the specified file. If append is true, the packets are
/// appended to an existing pcap file; otherwise, a new file is created.
pub fn run_export(
    rx_pcap: thingbuf::mpsc::blocking::Receiver<Packets, PacketsRecycler>,
    outfile: Option<String>,
    order_pcap: bool,
) {
    if let Some(outfile) = outfile {
        log::trace!("Start pcap export thread");
        let file_out = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&outfile)
            .expect("Error opening or creating file");
        let mut pcap_writer =
            PcapWriter::new(BufWriter::new(file_out)).expect("Error writing file");
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
    } else {
        // It is necessary to empty the channel, otherwise the generation will be stopped
        while rx_pcap.recv_ref().is_some() {}
    }
}
