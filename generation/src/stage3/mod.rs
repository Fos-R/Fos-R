#![allow(unused)]

use crate::icmp::*;
use crate::tcp::*;
use crate::udp::*;
use crate::ui::*;
use crate::*;
use crossbeam_channel::{Receiver, Sender};
use pcap::{Capture, PacketHeader};
use pnet_packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::{self, Ipv4Flags, MutableIpv4Packet};
use pnet_packet::tcp::{self, MutableTcpPacket, TcpFlags};
use pnet_packet::udp::{ipv4_checksum, MutableUdpPacket};
use rand_core::*;
use rand_pcg::Pcg32;

#[derive(Debug, Clone)]
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
    fn new(rng: &mut impl RngCore) -> Self {
        TcpPacketData {
            forward: rng.next_u32(),
            backward: rng.next_u32(),
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

    fn setup_ip_packet<P: PacketInfo>(
        &self,
        packet: &mut [u8],
        flow: &FlowData,
        packet_info: &P,
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
        rng: &mut impl RngCore,
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
                let mut payload = vec![0_u8; *size];
                rng.fill_bytes(&mut payload);
                tcp_packet.set_payload(payload.as_slice());
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

    fn setup_udp_packet(
        &self,
        rng: &mut Pcg32,
        packet: &mut [u8],
        flow: &FlowData,
        packet_info: &UDPPacketInfo,
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
                let mut payload = vec![0_u8; *size];
                rng.fill_bytes(&mut payload);
                udp_packet.set_payload(payload.as_slice());
            }
            Payload::Replay(payload) => {
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
    pub fn generate_tcp_packets(
        &self,
        input: SeededData<PacketsIR<TCPPacketInfo>>,
    ) -> SeededData<Packets> {
        let mut rng = Pcg32::seed_from_u64(input.seed);
        let ip_start = MutableEthernetPacket::minimum_packet_size();
        let tcp_start = ip_start + MutableIpv4Packet::minimum_packet_size();
        let flow = &input.data.flow.get_data();
        let mut tcp_data = TcpPacketData::new(&mut rng);
        let mut packets = Vec::with_capacity(input.data.packets_info.len());
        let mut directions = Vec::with_capacity(input.data.packets_info.len());

        for packet_info in &input.data.packets_info {
            let packet_size = MutableEthernetPacket::minimum_packet_size()
                + MutableIpv4Packet::minimum_packet_size()
                + MutableTcpPacket::minimum_packet_size()
                + packet_info.payload.get_payload_size();

            let mut packet = vec![0u8; packet_size];

            self.setup_ethernet_frame(&mut packet[..])
                .expect("Incorrect Ethernet frame");
            self.setup_ip_packet(&mut packet[ip_start..], flow, packet_info)
                .expect("Incorrect IP packet");
            tcp_data = self
                .setup_tcp_packet(
                    &mut rng,
                    &mut packet[tcp_start..],
                    flow,
                    packet_info,
                    tcp_data,
                )
                .expect("Incorrect TCP packet");

            packets.push(Packet {
                header: self.get_pcap_header(packet_size, packet_info.get_ts()),
                data: packet.clone(),
            });
            directions.push(packet_info.get_direction());
        }

        SeededData {
            seed: rng.next_u64(),
            data: Packets {
                packets,
                directions,
                flow: input.data.flow,
            },
        }
    }

    /// Generate UDP packets from an intermediate representation
    pub fn generate_udp_packets(
        &self,
        input: SeededData<PacketsIR<UDPPacketInfo>>,
    ) -> SeededData<Packets> {
        let mut rng = Pcg32::seed_from_u64(input.seed);
        let ip_start = MutableEthernetPacket::minimum_packet_size();
        let udp_start = ip_start + MutableIpv4Packet::minimum_packet_size();
        let flow = &input.data.flow.get_data();
        let mut tcp_data = TcpPacketData::new(&mut rng);
        let mut packets = Vec::new();
        let mut directions = Vec::new();

        for packet_info in &input.data.packets_info {
            let packet_size = MutableEthernetPacket::minimum_packet_size()
                + MutableIpv4Packet::minimum_packet_size()
                + MutableUdpPacket::minimum_packet_size()
                + packet_info.payload.get_payload_size();

            let mut packet = vec![0u8; packet_size];

            self.setup_ethernet_frame(&mut packet[..])
                .expect("Incorrect Ethernet frame");
            self.setup_ip_packet(&mut packet[ip_start..], flow, packet_info)
                .expect("Incorrect IP packet");
            self.setup_udp_packet(&mut rng, &mut packet[udp_start..], flow, packet_info)
                .expect("Incorrect TCP packet");

            packets.push(Packet {
                header: self.get_pcap_header(packet_size, packet_info.get_ts()),
                data: packet.clone(),
            });
            directions.push(packet_info.get_direction());
        }

        SeededData {
            seed: rng.next_u64(),
            data: Packets {
                packets,
                directions,
                flow: input.data.flow,
            },
        }
    }

    /// Generate ICMP packets from an intermediate representation
    pub fn generate_icmp_packets(
        &self,
        input: SeededData<PacketsIR<ICMPPacketInfo>>,
    ) -> SeededData<Packets> {
        let mut rng = Pcg32::seed_from_u64(input.seed);
        todo!()
    }
}

fn insert_noise(data: &mut SeededData<Packets>) {
    todo!()
}

fn pcap_export(mut data: Vec<Packet>, outfile: &str, append: bool) -> Result<(), pcap::Error> {
    let mut capture = Capture::dead(pcap::Linktype(1))?;
    let mut savefile = if append {
        capture.savefile_append(outfile)?
    } else {
        capture.savefile(outfile)?
    };
    // data.sort();
    // TODO: find a way to not write packets one by one...
    for packet in data {
        savefile.write(&pcap::Packet {
            header: &packet.header,
            data: &packet.data,
        });
    }
    savefile.flush();
    Ok(())
}

fn send_online(
    mut flow_packets: SeededData<Packets>,
    tx_s3_hm: &HashMap<Ipv4Addr, Sender<SeededData<Packets>>>,
) {
    // check if exist
    let f = flow_packets.data.flow.get_data();
    let src_s4 = tx_s3_hm.get(&f.src_ip);
    let dst_s4 = tx_s3_hm.get(&f.dst_ip);
    if let (Some(tx1), Some(tx2)) = (src_s4, dst_s4) {
        // only copy if we have to
        tx1.send(flow_packets.clone()).unwrap();
        // ensure stage 4 is always the source
        flow_packets.data.directions = flow_packets
            .data
            .directions
            .into_iter()
            .map(|d| d.into_reverse())
            .collect();
        tx2.send(flow_packets).unwrap();
    } else if let Some(tx1) = src_s4 {
        tx1.send(flow_packets).unwrap();
    } else if let Some(tx2) = dst_s4 {
        // ensure stage 4 is always the source
        flow_packets.data.directions = flow_packets
            .data
            .directions
            .into_iter()
            .map(|d| d.into_reverse())
            .collect();
        tx2.send(flow_packets).unwrap();
    }
}

fn send_pcap(flow_packets: SeededData<Packets>, tx_s3_to_collector: &Sender<Packets>) {
    let mut noisy_flow = SeededData {
        seed: flow_packets.seed,
        data: flow_packets.data,
    };
    // if noise { // insert noise // TODO: find a better way to do it
    //     stage3::insert_noise(&mut noisy_flow);
    // }
    tx_s3_to_collector.send(noisy_flow.data).unwrap();
}

pub fn run<T: PacketInfo>(
    generator: impl Fn(SeededData<PacketsIR<T>>) -> SeededData<Packets>,
    rx_s3: Receiver<SeededData<PacketsIR<T>>>,
    tx_s3_hm: HashMap<Ipv4Addr, Sender<SeededData<Packets>>>, // TODO: Option
    tx_s3_to_collector: Sender<Packets>,                      // TODO: Option
    stats: Arc<Stats>,
    online: bool,
    pcap_export: bool,
) {
    // Prepare stage 3
    log::trace!("Start S3");
    for headers in rx_s3 {
        let mut flow_packets = generator(headers);
        stats.increase(&flow_packets.data);
        // only copy the flows if we need to send it to online and pcap
        if online {
            if pcap_export {
                // TODO: le mode online a la priorité, donc peut-être ne pas se laisser bloquer par
                // l’export s’il prend trop de temps ?
                send_pcap(flow_packets.clone(), &tx_s3_to_collector)
            }
            send_online(flow_packets, &tx_s3_hm);
        } else if pcap_export {
            send_pcap(flow_packets, &tx_s3_to_collector)
        }
    }
    log::trace!("S3 stops");
}

pub fn run_collector(rx_collector: Receiver<Packets>, tx_collector: Sender<Vec<Packet>>) {
    log::trace!("Start pcap collector thread");
    let mut again = true;
    while again {
        let mut packets_record = Vec::with_capacity(10_010_000);
        while packets_record.len() < 10_000_000 {
            if let Ok(mut packets) = rx_collector.recv() {
                packets_record.append(&mut packets.packets);
            } else {
                again = false;
                break;
            }
        }
        tx_collector.send(packets_record).unwrap();
    }
}

pub fn run_export(rx_pcap: Receiver<Vec<Packet>>, outfile: &str) {
    log::trace!("Start pcap export thread");
    if let Ok(packets_record) = rx_pcap.recv() {
        log::trace!("Saving into {}", outfile);
        stage3::pcap_export(packets_record, outfile, false).expect("Error during pcap export!");
        for packets_record in rx_pcap {
            log::trace!("Saving into {}", outfile);
            pcap_export(packets_record, outfile, true).expect("Error during pcap export!");
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use pnet_packet::Packet;

    #[test]
    fn test_ethernet() {
        let stage3 = Stage3::new(false);
        let mut packet = [0u8; 200];
        let result = stage3.setup_ethernet_frame(&mut packet);
        assert_eq!(result, Some(()));
        let ethertype = ((packet[12] as u16) << 8) | (packet[13] as u16);
        assert_eq!(ethertype, 0x0800);
    }

    #[test]
    fn test_setup_ip_packet_forward() {
        let stage = Stage3::new(false);
        let mut packet = vec![0u8; MutableIpv4Packet::minimum_packet_size()];

        let flow_data = FlowData {
            src_ip: Ipv4Addr::new(192, 168, 1, 1),
            dst_ip: Ipv4Addr::new(192, 168, 1, 2),
            src_port: 12345,
            dst_port: 80,
            ttl_client: 64,
            ttl_server: 64,
            fwd_packets_count: 0,
            bwd_packets_count: 0,
            timestamp: Duration::new(0, 0),
            total_duration: Duration::new(0, 0),
        };

        let packet_info = TCPPacketInfo {
            payload: Payload::Empty,
            ts: Duration::new(0, 0),
            direction: PacketDirection::Forward,
            noise: NoiseType::None,
            s_flag: false,
            a_flag: false,
            f_flag: false,
            r_flag: false,
            u_flag: false,
            p_flag: false,
        };

        // Call the method under test
        stage
            .setup_ip_packet(&mut packet, &flow_data, &packet_info)
            .expect("Failed to setup IP packet");

        // Create a mutable IP packet from the packet buffer
        let ipv4_packet = MutableIpv4Packet::new(&mut packet).expect("Failed to create IP packet");

        // Assert the fields are set correctly
        assert_eq!(ipv4_packet.get_version(), 4);
        assert_eq!(ipv4_packet.get_header_length(), 5);
        //assert_eq!(ipv4_packet.get_total_length(), packet.len() as u16);
        assert_eq!(
            ipv4_packet.get_next_level_protocol(),
            IpNextHeaderProtocols::Tcp
        );
        assert_eq!(ipv4_packet.get_ttl(), flow_data.ttl_client);
        assert_eq!(ipv4_packet.get_source(), flow_data.src_ip);
        assert_eq!(ipv4_packet.get_destination(), flow_data.dst_ip);
        assert_eq!(ipv4_packet.get_flags(), Ipv4Flags::DontFragment);
    }

    #[test]
    fn test_setup_ip_packet_backward() {
        let stage = Stage3::new(false);
        let mut packet = vec![0u8; MutableIpv4Packet::minimum_packet_size()];

        let flow_data = FlowData {
            src_ip: Ipv4Addr::new(192, 168, 1, 1),
            dst_ip: Ipv4Addr::new(192, 168, 1, 2),
            src_port: 12345,
            dst_port: 80,
            ttl_client: 64,
            ttl_server: 64,
            fwd_packets_count: 0,
            bwd_packets_count: 0,
            timestamp: Duration::new(0, 0),
            total_duration: Duration::new(0, 0),
        };

        let packet_info = TCPPacketInfo {
            payload: Payload::Empty,
            ts: Duration::new(0, 0),
            direction: PacketDirection::Backward,
            noise: NoiseType::None,
            s_flag: false,
            a_flag: false,
            f_flag: false,
            r_flag: false,
            u_flag: false,
            p_flag: false,
        };

        // Call the method under test
        stage
            .setup_ip_packet(&mut packet, &flow_data, &packet_info)
            .expect("Failed to setup IP packet");

        // Create a mutable IP packet from the packet buffer
        let ipv4_packet = MutableIpv4Packet::new(&mut packet).expect("Failed to create IP packet");

        // Assert the fields are set correctly
        assert_eq!(ipv4_packet.get_version(), 4);
        assert_eq!(ipv4_packet.get_header_length(), 5);
        //assert_eq!(ipv4_packet.get_total_length(), packet.len() as u16);
        assert_eq!(
            ipv4_packet.get_next_level_protocol(),
            IpNextHeaderProtocols::Tcp
        );
        assert_eq!(ipv4_packet.get_ttl(), flow_data.ttl_server);
        assert_eq!(ipv4_packet.get_source(), flow_data.dst_ip);
        assert_eq!(ipv4_packet.get_destination(), flow_data.src_ip);
        assert_eq!(ipv4_packet.get_flags(), Ipv4Flags::DontFragment);
    }

    #[test]
    fn test_setup_tcp_packet() {
        let stage3 = Stage3::new(false);

        // Prepare the random number generator
        let mut rng = Pcg32::seed_from_u64(42);

        let flow = FlowData {
            src_ip: "192.168.1.1".parse().unwrap(),
            dst_ip: "192.168.1.2".parse().unwrap(),
            src_port: 12345,
            dst_port: 80,
            ttl_client: 64,
            ttl_server: 64,
            fwd_packets_count: 0,
            bwd_packets_count: 0,
            timestamp: Duration::new(0, 0),
            total_duration: Duration::new(0, 0),
        };

        let payload_size = 100;
        let packet_info = TCPPacketInfo {
            payload: Payload::Random(payload_size),
            ts: Duration::new(0, 0),
            direction: PacketDirection::Forward,
            noise: NoiseType::None,
            s_flag: true,
            a_flag: true,
            f_flag: false,
            r_flag: false,
            u_flag: false,
            p_flag: false,
        };

        let tcp_data = TcpPacketData::new(&mut Pcg32::seed_from_u64(42));

        // Prepare a mutable packet buffer
        let mut packet = vec![
            0u8;
            MutableEthernetPacket::minimum_packet_size()
                + MutableIpv4Packet::minimum_packet_size()
                + MutableTcpPacket::minimum_packet_size()
                + payload_size
        ];

        // Call the setup_tcp_packet method
        let new_tcp_data = stage3
            .setup_tcp_packet(
                &mut rng,
                &mut packet[MutableEthernetPacket::minimum_packet_size()
                    + MutableIpv4Packet::minimum_packet_size()..],
                &flow,
                &packet_info,
                tcp_data,
            )
            .expect("Failed to setup TCP packet");

        // Validate the TCP packet
        let tcp_packet = MutableTcpPacket::new(
            &mut packet[MutableEthernetPacket::minimum_packet_size()
                + MutableIpv4Packet::minimum_packet_size()..],
        )
        .unwrap();

        // Check fields
        assert_eq!(tcp_packet.get_source(), flow.src_port);
        assert_eq!(tcp_packet.get_destination(), flow.dst_port);
        assert_eq!(
            tcp_packet.get_sequence() + payload_size as u32,
            new_tcp_data.forward
        );
        assert_eq!(tcp_packet.get_acknowledgement(), new_tcp_data.backward);
        assert!(tcp_packet.get_flags() & TcpFlags::SYN != 0);
        assert!(tcp_packet.get_flags() & TcpFlags::ACK != 0);
        assert_eq!(tcp_packet.payload().len(), payload_size);
        assert!(new_tcp_data.forward > 0);
    }

    #[test]
    fn test_generate_tcp_packets() {
        // Setup the test data
        let flow_data = FlowData {
            src_ip: Ipv4Addr::new(192, 168, 1, 1),
            dst_ip: Ipv4Addr::new(192, 168, 1, 2),
            src_port: 12345,
            dst_port: 80,
            ttl_client: 64,
            ttl_server: 64,
            fwd_packets_count: 10,
            bwd_packets_count: 10,
            timestamp: Duration::new(0, 0),
            total_duration: Duration::new(10, 0),
        };

        let packet_info = TCPPacketInfo {
            payload: Payload::Random(100),
            ts: Duration::new(1, 0),
            direction: PacketDirection::Forward,
            noise: NoiseType::None,
            s_flag: true,
            a_flag: true,
            f_flag: false,
            r_flag: false,
            u_flag: false,
            p_flag: false,
        };

        let packets_ir = PacketsIR {
            packets_info: vec![packet_info.clone()],
            flow: Flow::TCP(flow_data),
        };

        let input = SeededData {
            seed: 42,
            data: packets_ir,
        };

        let stage3 = Stage3::new(false);

        // Call the method under test
        let result = stage3.generate_tcp_packets(input);

        // Validate the result
        assert_eq!(result.data.packets.len(), 1);

        let packet = &result.data.packets[0];
        assert_eq!(packet.header.caplen, packet.data.len() as u32);
        assert_eq!(
            packet.data.len(),
            MutableEthernetPacket::minimum_packet_size()
                + MutableIpv4Packet::minimum_packet_size()
                + MutableTcpPacket::minimum_packet_size()
                + packet_info.payload.get_payload_size() as usize
        );
    }
}
