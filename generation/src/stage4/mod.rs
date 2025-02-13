#![allow(unused)]

use std::net::{TcpListener, TcpStream};
use std::{
    cmp::Ordering,
    collections::{binary_heap, BinaryHeap},
};

use crate::*;
use crossbeam_channel::Receiver;
use pnet::transport::{
    ipv4_packet_iter, tcp_packet_iter, transport_channel, TransportChannelType, TransportReceiver,
    TransportSender,
};
use pnet_packet::{ip::IpNextHeaderProtocols, Packet};
use std::sync::Mutex;

pub struct Stage4 {
    // Params
    interface: Ipv4Addr,
    proto: Protocol,

    // Raw Socket
    tx: TransportSender,
    rx: TransportReceiver,

    // Flows
    current_flows: Arc<Mutex<BinaryHeap<OnlineFlow>>>,
}

struct OnlineFlow {
    flow: SeededData<Packets>,
    direction: PacketDirection,
}

// Used to order packets by timestamp in a binary heap
impl Ord for OnlineFlow {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.flow.data.packets.is_empty() {
            return Ordering::Greater;
        } else if other.flow.data.packets.is_empty() {
            return Ordering::Less;
        }
        self.flow.data.packets[0].cmp(&other.flow.data.packets[0])
    }
}

impl PartialOrd for OnlineFlow {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for OnlineFlow {
    fn eq(&self, other: &Self) -> bool {
        self.flow.data.packets.is_empty() && other.flow.data.packets.is_empty()
            || self.flow.data.packets[0] == other.flow.data.packets[0]
    }
}

impl Eq for OnlineFlow {}

impl Stage4 {
    pub fn new(interface: Ipv4Addr, proto: Protocol) -> Self {
        // Create an l3 raw socket using libpnet
        let ip_next_header_protocol = match proto {
            Protocol::TCP => IpNextHeaderProtocols::Tcp,
            Protocol::UDP => IpNextHeaderProtocols::Udp,
            Protocol::ICMP => IpNextHeaderProtocols::Icmp,
            _ => todo!("Handle error"),
        };

        let channel_type = TransportChannelType::Layer3(ip_next_header_protocol);

        let (mut tx, mut rx) = match transport_channel(4096, channel_type) {
            Ok((tx, rx)) => (tx, rx),
            Err(e) => panic!(
                "An error occurred when creating the transport channel: {}",
                e
            ),
        };

        let current_flows = Arc::new(Mutex::new(BinaryHeap::new()));

        Stage4 {
            interface,
            proto,
            tx,
            rx,
            current_flows,
        }
    }

    pub fn handle_packets(&mut self) {
        // Send and receive packets in this thread
        let mut rx_iter = ipv4_packet_iter(&mut self.rx);
        loop {
            // Peek the first flow of the heap
            let Some(mut current_flow) = self.current_flows.lock().unwrap().pop() else {
                continue;
                // Wait for a flow to be added maybe using a condition variable
            };

            // Get the first packet of the flow
            let packet = current_flow.flow.data.packets.remove(0);
            let direction = current_flow.flow.data.directions.remove(0);

            // Get the expected time of arrival of the packet to know if we should wait before sending or receiving it

            let eth_packet = pnet::packet::ethernet::EthernetPacket::new(&packet.data).unwrap();
            let ipv4_packet = pnet::packet::ipv4::Ipv4Packet::new(eth_packet.payload()).unwrap();
            let tcp_packet = pnet::packet::tcp::TcpPacket::new(ipv4_packet.payload()).unwrap();

            let destination = std::net::IpAddr::V4(ipv4_packet.get_destination());

            if direction == current_flow.direction {
                let ts = packet.header.ts;
                let now = std::time::SystemTime::now();
                let now = now.duration_since(std::time::UNIX_EPOCH).unwrap();
                let expected_ts = std::time::Duration::new(ts.tv_sec as u64, ts.tv_usec as u32);
                let remaining = expected_ts
                    .checked_sub(now)
                    .unwrap_or(std::time::Duration::new(0, 0));
                log::info!("Expected ts: {:?}", remaining);
                // Sleep for the remaining time
                std::thread::sleep(remaining);
                // Send the packet
                log::info!("Sending packet to {:?}", destination);
                log::info!("Packet: {:?}", tcp_packet.get_source());
                match self.tx.send_to(&ipv4_packet, destination) {
                    Ok(n) => assert_eq!(n, ipv4_packet.packet().len()), // Check if the whole packet was sent
                    Err(e) => panic!("failed to send packet: {}", e),
                }
            } else {
                log::info!("Waiting for packet from {:?}", ipv4_packet.get_source());
                // If the direction doesn't match, wait for the packet to be received
                while let Ok((recv_packet, addr)) = rx_iter.next() {
                    log::info!(
                        "Attempting to receive a packet, received packet from {:?}",
                        addr
                    );
                    let recv_tcp_packet = pnet::packet::tcp::TcpPacket::new(recv_packet.payload())
                        .expect("Failed to parse received packet");
                    // Let's compare the received packet with the one we're waiting for
                    if recv_tcp_packet.get_source() == tcp_packet.get_source() {
                        if recv_tcp_packet.get_destination() == tcp_packet.get_destination() {
                            if addr == ipv4_packet.get_source() {
                                // If the received packet matches the one we're waiting for, we can send it
                                log::info!("Received packet from {:?}", addr);
                                break;
                            } else {
                                log::info!(
                                    "Source address mismatch: expected {:?}, got {:?}",
                                    ipv4_packet.get_source(),
                                    addr
                                );
                            }
                        } else {
                            log::info!(
                                "Destination port mismatch: expected {:?}, got {:?}",
                                tcp_packet.get_destination(),
                                recv_tcp_packet.get_destination()
                            );
                        }
                    } else {
                        log::info!(
                            "Source port mismatch: expected {:?}, got {:?}",
                            tcp_packet.get_source(),
                            recv_tcp_packet.get_source()
                        );
                    }
                }
            }

            // Add the flow back to the heap if it still has packets
            if !current_flow.flow.data.packets.is_empty() {
                self.current_flows.lock().unwrap().push(current_flow);
            }
        }
    }

    pub fn handle_packet(&mut self) {
        loop {
            // Peek the first flow of the heap
            let Some(mut current_flow) = self.current_flows.lock().unwrap().pop() else {
                continue;
                // Wait for a flow to be added maybe using a condition variable
            };

            // Get the first packet of the flow
            let packet = current_flow.flow.data.packets.remove(0);
            let direction = current_flow.flow.data.directions.remove(0);

            let eth_packet = pnet::packet::ethernet::EthernetPacket::new(&packet.data).unwrap();
            let packet = pnet::packet::ipv4::Ipv4Packet::new(eth_packet.payload()).unwrap();
            let tcp_packet = pnet::packet::tcp::TcpPacket::new(packet.payload()).unwrap();

            // Send the packet to the destination
            let destination = std::net::IpAddr::V4(packet.get_destination());

            self.tx.send_to(packet, destination).unwrap();

            break;
        }
    }

    pub fn start(&mut self, mut incoming_flows: Receiver<SeededData<Packets>>) {
        log::info!("stage4 started on interface {}", self.interface);
        // Create a thread to receive incoming flows and add them to the current_flows
        let mut current_flows = self.current_flows.clone();
        let interface = self.interface;
        let join_handle = std::thread::spawn(move || {
            while let Ok(flow) = incoming_flows.recv() {
                log::info!("Received a new flow");

                // Get the flow's direction by peeking the first packet sender ip
                let direction = if flow.data.flow.get_data().src_ip == interface {
                    PacketDirection::Forward
                } else {
                    PacketDirection::Backward
                };

                log::info!(
                    "Number of flows in the heap: {}",
                    current_flows.lock().unwrap().len() + 1
                );

                if let Flow::TCP(tcp_flow) = &flow.data.flow {
                    let src_port = tcp_flow.src_port;
                    let dst_port = tcp_flow.dst_port;

                    let src_addr = format!("0.0.0.0:{}", src_port);
                    let dst_addr = format!("0.0.0.0:{}", dst_port);

                    let src_listener = TcpListener::bind(&src_addr);
                    match src_listener {
                        Ok(listener) => {
                            std::thread::spawn(move || {
                                for stream in listener.incoming() {
                                    match stream {
                                        Ok(stream) => {
                                            log::info!("New connection: {:?}", stream);
                                        }
                                        Err(e) => {
                                            log::error!("Error accepting connection: {:?}", e);
                                        }
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            log::error!("Error binding to address {:?}: {:?}", src_addr, e);
                        }
                    }

                    let dst_listener = TcpListener::bind(&dst_addr);
                    match dst_listener {
                        Ok(listener) => {
                            std::thread::spawn(move || {
                                for stream in listener.incoming() {
                                    match stream {
                                        Ok(stream) => {
                                            log::info!("New connection: {:?}", stream);
                                        }
                                        Err(e) => {
                                            log::error!("Error accepting connection: {:?}", e);
                                        }
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            log::error!("Error binding to address {:?}: {:?}", dst_addr, e);
                        }
                    }
                }

                current_flows
                    .lock()
                    .unwrap()
                    .push(OnlineFlow { flow, direction });
            }
        });

        // Handle packets
        self.handle_packets();
    }
}
