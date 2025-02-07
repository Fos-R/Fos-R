#![allow(unused)]

use std::collections::BinaryHeap;

use pnet::transport::{
    transport_channel, TransportChannelType, TransportReceiver, TransportSender,
};
use pnet_packet::ip::IpNextHeaderProtocols;

use crate::*;

pub struct Stage4 {
    interface: Ipv4Addr,
    proto: u8,

    raw_socket_tx: TransportSender,
    raw_socket_rx: TransportReceiver,
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

        Stage4 {
            interface,
            proto,
            raw_socket_tx,
            raw_socket_rx,
        }
    }

    pub fn send(&self, packets: SeededData<Packets>) {
        // send packets related to one flow
        // flow contains the metadata to configure the socket
        // before sending the next packet, we need to wait for the answer
        // we should reemit packet after a timeout in case we do not receive the answer
        // the part must be cross-platform and use raw socket
        todo!()
    }
}
