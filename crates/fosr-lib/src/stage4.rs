// use crate::config::Hosts;
use crate::icmp::*;
use crate::stats::Stats;
use crate::structs::*;
use crate::tcp::TCPPacketInfo;
use crate::udp::*;

use crossbeam_channel::{Receiver, Sender};
use pcap_file::PcapError;
use pcap_file::pcap::{PcapPacket, PcapWriter};
use pnet::util::MacAddr;
use pnet_packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet_packet::ip::IpNextHeaderProtocol;
use pnet_packet::ipv4::{self, MutableIpv4Packet};
use pnet_packet::tcp::{self, MutableTcpPacket, TcpFlags};
use pnet_packet::udp::MutableUdpPacket;
use rand_core::*;
use rand_pcg::Pcg32;
use std::io::BufWriter;
use std::net::Ipv4Addr;
use std::num::Wrapping;
use std::sync::Arc;
use std::time::Duration;

// const TEMPORARY_FILE_THRESHOLD: usize = 100_000;

/// Stage 4: generate full packets from packet metadata
#[derive(Debug, Clone)]
pub struct Stage4 {
    taint: bool,
    // config: Hosts,
    zero: MacAddr,
}

#[derive(Debug, Clone)]
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

impl Stage4 {
    /// Configures the Ethernet frame by setting the source, destination MAC addresses,
    /// and setting the EtherType to IPv4.
    fn setup_ethernet_frame(&self, packet: &mut [u8], src_mac: &MacAddr, dst_mac: &MacAddr) {
        // the size is already computed, it cannot fail
        let mut eth_packet = MutableEthernetPacket::new(packet).unwrap();
        eth_packet.set_ethertype(EtherTypes::Ipv4);
        eth_packet.set_source(*src_mac);
        eth_packet.set_destination(*dst_mac);
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
    ) {
        let len = packet.len();
        // cannot fail
        let mut ipv4_packet = MutableIpv4Packet::new(packet).unwrap();

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
        tcp_data: &mut TcpPacketData, // TODO Change to take ownership of tcp_data
        payload_array: &mut [u8; 65536],
    ) {
        // Return TcpPacketData and an empty tuple
        let mut tcp_packet = MutableTcpPacket::new(packet).unwrap();

        match packet_info.get_direction() {
            PacketDirection::Forward => {
                // Set the source and destination ports
                tcp_packet.set_source(flow.src_port);
                tcp_packet.set_destination(flow.dst_port);

                // Set sequence and acknowledgement numbers
                tcp_packet.set_sequence(tcp_data.forward.0);
                if packet_info.a_flag {
                    tcp_packet.set_acknowledgement(tcp_data.backward.0);
                }

                // Increment forward ACK and backward SEQ
                if packet_info.s_flag {
                    tcp_data.forward += 1;
                } else {
                    tcp_data.forward += packet_info.payload.get_payload_size() as u32;
                }
            }
            PacketDirection::Backward => {
                // Set the source and destination ports
                tcp_packet.set_source(flow.dst_port);
                tcp_packet.set_destination(flow.src_port);

                // Set sequence and acknowledgement numbers
                tcp_packet.set_sequence(tcp_data.backward.0);
                if packet_info.a_flag {
                    tcp_packet.set_acknowledgement(tcp_data.forward.0);
                }

                if packet_info.s_flag {
                    tcp_data.backward += 1;
                } else {
                    tcp_data.backward += packet_info.payload.get_payload_size() as u32;
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
            tcp_data.ssthresh = tcp_data.cwnd / 2; // Halve the threshold
            tcp_data.cwnd = tcp_data.ssthresh; // Enter congestion avoidance
            cwr_flag = true; // Indicate CWR flag should be set
        } else if tcp_data.cwnd < tcp_data.ssthresh {
            // Slow start: Exponential increase
            tcp_data.cwnd += tcp_data.mss;
        } else {
            // Congestion avoidance: Linear increase
            tcp_data.cwnd += (tcp_data.mss * tcp_data.mss) / tcp_data.cwnd;
        }

        // Set the window size
        let effective_window = tcp_data.cwnd.min(tcp_data.rwnd) as u16;
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
    ) {
        let mut udp_packet = MutableUdpPacket::new(packet).unwrap();

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
    }

    pub fn new(taint: bool /*config: Hosts*/) -> Self {
        Stage4 {
            taint,
            // config,
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
        packet: &mut [u8; 65536],
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

            let mut mac_src = &self.zero;
            let mut mac_dst = &self.zero;
            // let mut mac_src = self.config.get_mac(&flow.src_ip).unwrap_or(&self.zero);
            // let mut mac_dst = self.config.get_mac(&flow.dst_ip).unwrap_or(&self.zero);
            if matches!(packet_info.get_direction(), PacketDirection::Backward) {
                (mac_src, mac_dst) = (mac_dst, mac_src);
            }

            packet[..packet_size].fill(0);
            self.setup_ethernet_frame(&mut packet[..packet_size], mac_src, mac_dst);
            self.setup_ip_packet(
                &mut rng,
                &mut packet[ip_start..packet_size],
                &input.data.flow,
                packet_info,
            );
            self.setup_tcp_packet(
                &mut rng,
                &mut packet[tcp_start..packet_size],
                flow,
                packet_info,
                &mut tcp_data,
                payload_array,
            );

            packets.packets.push(Packet {
                timestamp: packet_info.get_ts(),
                data: packet[..packet_size].to_vec(),
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
        packet: &mut [u8; 65536],
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

            packet[..packet_size].fill(0);
            self.setup_ethernet_frame(
                &mut packet[..packet_size],
                &self.zero,
                &self.zero,
                // self.config.get_mac(&flow.src_ip).unwrap_or(&self.zero),
                // self.config.get_mac(&flow.dst_ip).unwrap_or(&self.zero),
            );
            self.setup_ip_packet(
                &mut rng,
                &mut packet[ip_start..packet_size],
                &input.data.flow,
                packet_info,
            );
            self.setup_udp_packet(
                &mut rng,
                &mut packet[udp_start..packet_size],
                flow,
                packet_info,
                payload_array,
            );

            packets.packets.push(Packet {
                timestamp: packet_info.get_ts(),
                data: packet[..packet_size].to_vec(),
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
        packet: &mut [u8; 65536],
        payload_array: &mut [u8; 65536],
    ) {
        // let mut rng = Pcg32::seed_from_u64(input.seed);
        todo!()
    }
}

// fn insert_noise(data: &mut SeededData<Packets>) {
//     todo!()
// }

pub fn send_online(
    local_interfaces: &[Ipv4Addr],
    mut flow_packets: Packets,
    tx_s4: &Sender<Packets>,
) {
    // check if exist
    let f = flow_packets.flow.get_data();
    let src_s5 = local_interfaces.contains(&f.src_ip);
    let dst_s5 = local_interfaces.contains(&f.dst_ip);
    if src_s5 && dst_s5 {
        log::trace!("Both source and destination IP are local");
        // only copy if we have to
        tx_s4.send(flow_packets.clone()).unwrap();
        // ensure this host is always the source
        flow_packets.reverse();
        tx_s4.send(flow_packets).unwrap();
    } else if src_s5 {
        log::trace!("Source IP is local");
        tx_s4.send(flow_packets).unwrap();
    } else if dst_s5 {
        log::trace!("Destination IP is local");
        // ensure this host is always the source
        flow_packets.reverse();
        tx_s4.send(flow_packets).unwrap();
    }
}

/// Sends a packet flow to the pcap pcap channel.
///
/// This function forwards the provided packet flow to the pcap, where it
/// may be further processed (for example, noise insertion) before export.
fn send_pcap(flow_packets: thingbuf::mpsc::blocking::SendRef<Packets>) {
    // if noise { // insert noise // TODO: find a better way to do it
    //     stage4::insert_noise(&mut noisy_flow);
    // }
    drop(flow_packets); // actually send (the drop in itself is useless but easier to read)
    // tx_s4_to_pcap.send(flow_packets).unwrap();
}

/// Runs stage 4 of the pipeline, processing incoming seeded packet representations.
///
/// This function receives intermediate packet data from rx_s4, generates complete
/// packets using the provided generator function, and then sends the generated flows
/// to appropriate channels based on the configuration (online transmission and/or pcap export).
pub fn run_channel<T: PacketInfo>(
    generator: impl Fn(&SeededData<PacketsIR<T>>, &mut Packets, &mut [u8; 65536], &mut [u8; 65536]),
    local_interfaces: Vec<Ipv4Addr>,
    rx_s4: Receiver<SeededData<PacketsIR<T>>>,
    tx_s4: Option<Sender<Packets>>,
    tx_s4_to_pcap: thingbuf::mpsc::blocking::Sender<Packets, PacketsRecycler>, // TODO: Option
    stats: Arc<Stats>,
    pcap_export: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Prepare stage 4
    log::trace!("Start S4");

    let mut payload_array: [u8; 65536] = [0; 65536]; // to avoid allocating Vec for payloads
    // everytime. 65536 is the maximum payload
    // size.
    let mut packet: [u8; 65536] = [0; 65536]; // used to avoid initializing the packet to 0

    for headers in rx_s4 {
        // log::trace!("Creating packets");
        let mut flow_packets = tx_s4_to_pcap.send_ref()?;
        // flow_packets.clear();
        generator(&headers, &mut flow_packets, &mut packet, &mut payload_array);
        flow_packets.flow = headers.data.flow;
        stats.increase(&flow_packets);

        // only copy the flows if we need to send it to online and pcap
        if let Some(ref tx_s4) = tx_s4 {
            send_online(&local_interfaces, flow_packets.clone(), tx_s4);
        }
        if pcap_export {
            send_pcap(flow_packets);
        }
        if stats.should_stop() {
            break;
        }
    }
    log::trace!("S4 stops");
    Ok(())
}

/// Complete the packets and collect them into a vector
pub fn run_vec<T: PacketInfo>(
    generator: impl Fn(&SeededData<PacketsIR<T>>, &mut Packets, &mut [u8; 65536], &mut [u8; 65536]),
    vec_s4: Vec<SeededData<PacketsIR<T>>>,
    stats: Arc<Stats>,
) -> Vec<Packet> {
    let mut payload_array: [u8; 65536] = [0; 65536]; // to avoid allocating Vec for payloads
    let mut packet: [u8; 65536] = [0; 65536];
    let mut all_packets: Vec<Packet> =
        Vec::with_capacity(vec_s4.iter().map(|h| h.data.packets_info.len()).sum());
    let mut initial_ts: Option<Duration> = None;

    for headers in vec_s4 {
        let new_ts = headers.data.flow.get_data().timestamp;
        if let Some(ts) = initial_ts {
            if new_ts < ts {
                initial_ts = Some(new_ts)
            }
        } else {
            initial_ts = Some(new_ts)
        }
        let mut flow_packets = Packets::default();
        stats.set_current_duration(new_ts.as_secs() - initial_ts.unwrap().as_secs());

        generator(&headers, &mut flow_packets, &mut packet, &mut payload_array);
        stats.increase(&flow_packets);

        for packet in flow_packets.packets.into_iter() {
            all_packets.push(packet);
        }
    }

    all_packets
}

/// Convert a Vec<Packet> into a Vec<u8> containing the bytes of a pcap file
pub fn to_pcap_vec(vec: &Vec<Packet>) -> Result<Vec<u8>, PcapError> {
    let mut pcap_writer = PcapWriter::new(BufWriter::new(Vec::new()))?;
    for packet in vec {
        pcap_writer
            .write_packet(&PcapPacket::new(
                packet.timestamp,
                packet.data.len() as u32,
                &packet.data,
            ))
            .unwrap();
    }
    Ok(pcap_writer.into_writer().into_inner().unwrap())
}
