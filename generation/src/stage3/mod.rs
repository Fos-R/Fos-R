#![allow(unused)]

use crate::*;
use crate::tcp::*;
use crate::udp::*;
use crate::icmp::*;
use rand_pcg::Pcg32;
use rand::prelude::*;
use pcap::{Capture, Packet, PacketHeader};
use pnet_packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::{self, Ipv4Flags, MutableIpv4Packet};
use pnet_packet::tcp::{self, MutableTcpPacket, TcpFlags};

pub struct Stage3 {
    rng: Pcg32,
} // In the future, add network/system configuration here

impl Stage3 {

    fn setup_ethernet_frame(&self, packet: &mut [u8]) -> Option<()> {
        let mut eth_packet = MutableEthernetPacket::new(packet)?;
        eth_packet.set_ethertype(EtherTypes::Ipv4);

        Some(())
    }

    fn setup_ip_packet(&self, packet: &mut [u8], flow: FlowData, packet_info: &TCPPacketInfo) -> Option<()> {
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
                ipv4_packet.set_ttl(flow.recorded_ttl_client);
                ipv4_packet.set_source(flow.src_ip);
                ipv4_packet.set_destination(flow.dst_ip);
            }
            PacketDirection::Backward => {
                ipv4_packet.set_ttl(flow.recorded_ttl_server);
                ipv4_packet.set_source(flow.dst_ip);
                ipv4_packet.set_destination(flow.src_ip);
            }
        }

        // Set the flags
        ipv4_packet.set_flags(Ipv4Flags::DontFragment); // TODO: Set fragmentation based on the window size ??

        // Compute the checksum
        ipv4_packet.set_checksum(ipv4::checksum(&ipv4_packet.to_immutable()));

        Some(())
    }

    fn setup_tcp_packet(&mut self, packet: &mut [u8], flow: FlowData, packet_info: &TCPPacketInfo, forward: u32, backward: u32) -> Option<()> {
        let mut tcp_packet = MutableTcpPacket::new(packet)?;

        match packet_info.get_direction() {
            PacketDirection::Forward => {
                // Set the source and destination ports
                tcp_packet.set_source(flow.src_port);
                tcp_packet.set_destination(flow.dst_port);

                // Set sequence and acknowledgement numbers
                tcp_packet.set_sequence(forward);
                if packet_info.a_flag {
                    tcp_packet.set_acknowledgement(backward);
                }

                // Increment forward ACK and backward SEQ
                forward += packet_info.payload.get_payload_size() as u32;
            }
            PacketDirection::Backward => {
                // Set the source and destination ports
                tcp_packet.set_source(flow.dst_port);
                tcp_packet.set_destination(flow.src_port);

                // Set sequence and acknowledgement numbers
                tcp_packet.set_sequence(backward);
                if packet_info.a_flag {
                    tcp_packet.set_acknowledgement(forward);
                }

                backward += packet_info.payload.get_payload_size() as u32;
            }
        }

        // Set the payload
        match packet_info.payload {
            Payload::Empty => (),
            Payload::Random(size) => {
                let mut rng = rand::thread_rng();
                let payload: Vec<u8> = (0..size).map(|_| rng.gen()).collect();
                tcp_packet.set_payload(payload.as_slice());
            }
            Payload::Replay(_) => (),
        }

        // Set the s | a | f | r | u | p flags
        tcp_packet.set_flags(
            (packet_info.s_flag as u8 * TcpFlags::SYN as u8)
                | (packet_info.a_flag as u8 * TcpFlags::ACK as u8)
                | (packet_info.f_flag as u8 * TcpFlags::FIN as u8)
                | (packet_info.r_flag as u8 * TcpFlags::RST as u8)
                | (packet_info.u_flag as u8 * TcpFlags::URG as u8)
                | (packet_info.p_flag as u8 * TcpFlags::PSH as u8),
        );

        // Simulate the congestion window
        let mut cwr_flag = false;
        if rand::random::<f32>() < 0.05 {
            // 5% chance of congestion
            self.ssthresh = self.cwnd / 2; // Halve the threshold
            self.cwnd = self.ssthresh; // Enter congestion avoidance
            cwr_flag = true; // Indicate CWR flag should be set
        } else if self.cwnd < self.ssthresh {
            // Slow start: Exponential increase
            self.cwnd += self.mss;
        } else {
            // Congestion avoidance: Linear increase
            self.cwnd += (mss * mss) / self.cwnd;
        }

        // Set the window size
        let effective_window = cwnd.min(self.rwnd) as u16;
        tcp_packet.set_window(effective_window); // TODO: Compute the correct window size

        // Set the CWR flag if congestion occurred
        if cwr_flag {
            tcp_packet.set_flags(tcp_packet.get_flags() | TcpFlags::CWR as u8);
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

        Some(())
    }


    pub fn new(seed: u64) -> Self {
        Stage3 { rng: Pcg32::seed_from_u64(seed) }
    }

    /// Generate TCP packets from an intermediate representation
    pub fn generate_tcp_packets(&self, input: &PacketsIR<TCPPacketInfo>) -> Vec<Packet> {
        panic!("Not implemented");
    }

    /// Generate UDP packets from an intermediate representation
    pub fn generate_udp_packets(&self, input: &PacketsIR<UDPPacketInfo>) -> Vec<Packet> {
        panic!("Not implemented");
    }

    /// Generate ICMP packets from an intermediate representation
    pub fn generate_icmp_packets(&self, input: &PacketsIR<ICMPPacketInfo>) -> Vec<Packet> {
        panic!("Not implemented");
    }

}
