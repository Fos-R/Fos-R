#![allow(unused)]

use std::{
    collections::BinaryHeap,
    net::Ipv4Addr,
    sync::{Arc, Mutex},
    thread::{JoinHandle, ThreadId},
    time::{Duration, SystemTime},
};

use crossbeam_channel::Receiver;
use ongoing_flow::OngoingFlow;
use pnet::transport::{
    ipv4_packet_iter, transport_channel, TransportChannelType, TransportReceiver, TransportSender,
};
use pnet_packet::{
    ethernet::EthernetPacket, ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, tcp::TcpPacket, Packet,
};

use crate::{PacketDirection, Packets, SeededData, ICMP_PROTO, TCP_PROTO, UDP_PROTO};

mod ongoing_flow;

pub struct Stage4 {
    interface: Ipv4Addr,
    proto: u8,

    raw_socket_tx: TransportSender,
    raw_socket_rx: TransportReceiver,

    ongoing_flows: Arc<Mutex<BinaryHeap<OngoingFlow>>>,
}

impl Stage4 {
    pub fn new(interface: Ipv4Addr, proto: u8) -> Self {
        let ip_next_header_protocol = match proto {
            TCP_PROTO => IpNextHeaderProtocols::Tcp,
            UDP_PROTO => IpNextHeaderProtocols::Udp,
            ICMP_PROTO => IpNextHeaderProtocols::Icmp,
            _ => todo!("Unsupported protocol"),
        };

        let channel_type = TransportChannelType::Layer3(ip_next_header_protocol);

        let (raw_socket_tx, raw_socket_rx) = match transport_channel(4096, channel_type) {
            Ok((tx, rx)) => (tx, rx),
            Err(e) => panic!(
                "An error occurred when creating the transport channel: {}",
                e
            ),
        };

        let ongoing_flows = Arc::new(Mutex::new(BinaryHeap::new()));

        Stage4 {
            interface,
            proto,
            raw_socket_tx,
            raw_socket_rx,
            ongoing_flows,
        }
    }

    fn listen_for_new_flows(
        &mut self,
        mut new_flows_rx: Receiver<SeededData<Packets>>,
    ) -> JoinHandle<()> {
        let thread_id = std::thread::current().id();
        let ongoing_flows = self.ongoing_flows.clone();
        let interface = self.interface;
        std::thread::spawn(move || {
            while let Ok(flow) = new_flows_rx.recv() {
                log::trace!("Stage 4 ({:?} received a new flow", thread_id);

                // Get the flow's direction by peeking the first packet sender ip
                let direction = if flow.data.flow.get_data().src_ip == interface {
                    PacketDirection::Forward
                } else {
                    PacketDirection::Backward
                };

                ongoing_flows
                    .lock()
                    .unwrap()
                    .push(OngoingFlow { flow, direction });
            }
        })
    }

    fn process_flows(&mut self) {
        let thread_id = std::thread::current().id();

        loop {
            let Some(mut ongoing_flow) = self.ongoing_flows.lock().unwrap().pop() else {
                std::thread::sleep(std::time::Duration::from_millis(100)); // TODO: use a condition variable to wake up the thread when a new flow is added
                continue;
            };

            let packet = ongoing_flow.flow.data.packets.remove(0);
            let direction = ongoing_flow.flow.data.directions.remove(0);

            let eth_packet = EthernetPacket::new(&packet.data).unwrap();
            let ipv4_packet = Ipv4Packet::new(eth_packet.payload()).unwrap();

            let destination = std::net::IpAddr::V4(ipv4_packet.get_destination());

            if direction == ongoing_flow.direction {
                self.send_packet(packet.header.ts, ipv4_packet, destination);
            } else {
                self.wait_for_packet(thread_id, ipv4_packet);
            }
        }
    }

    fn wait_for_packet(&mut self, thread_id: ThreadId, ipv4_packet: Ipv4Packet<'_>) {
        log::trace!("Waiting for packet from {:?}", ipv4_packet.get_source());

        let expected_tcp_packet = TcpPacket::new(ipv4_packet.payload()).unwrap();

        let mut incomping_ipv4_packets = ipv4_packet_iter(&mut self.raw_socket_rx);

        while let Ok((recv_packet, addr)) = incomping_ipv4_packets.next() {
            let Some(recv_tcp_packet) = TcpPacket::new(recv_packet.payload()) else {
                log::error!("Stage 4 ({:?}): Received malformed Tcp packet", thread_id);
                continue;
            };

            if ipv4_packet.get_source() == addr
                && recv_tcp_packet.get_destination() == expected_tcp_packet.get_destination()
                && recv_tcp_packet.get_source() == expected_tcp_packet.get_source()
            {
                log::trace!("Correctly received packet from {:?}", addr);
                break;
            }
        }
    }

    fn send_packet(
        &mut self,
        packet_ts: libc::timeval,
        ipv4_packet: pnet_packet::ipv4::Ipv4Packet<'_>,
        destination: std::net::IpAddr,
    ) {
        let time_before_send = Duration::new(packet_ts.tv_sec as u64, packet_ts.tv_usec as u32)
            .checked_sub(
                SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap(),
            )
            .unwrap_or_default();

        log::trace!(
            "Stage 4 ({:?}): Sending packet to {:?} in {} ms",
            std::thread::current().id(),
            destination,
            time_before_send.as_millis()
        );

        std::thread::sleep(time_before_send);

        match self.raw_socket_tx.send_to(&ipv4_packet, destination) {
            Ok(n) => assert_eq!(n, ipv4_packet.packet().len()), // Check if the whole packet was sent
            Err(e) => log::error!("Error sending packet: {}", e),
        }
    }

    pub fn start(&mut self, rx: Receiver<SeededData<Packets>>) {
        let new_flows_thread = self.listen_for_new_flows(rx);

        self.process_flows();

        new_flows_thread.join().unwrap();
    }
}
