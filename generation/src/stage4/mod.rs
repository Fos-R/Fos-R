#![allow(unused)]

use std::collections::HashMap;
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
use std::time::Duration;

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct FlowId {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
}

impl FlowId {
    pub fn is_compatible(&self, f: &Flow) -> bool {
        let d = f.get_data();
        self.src_ip == d.src_ip
            && self.dst_ip == d.dst_ip
            && self.src_port == d.src_port
            && self.dst_port == d.dst_port
    }
}

pub struct Stage4 {
    // Params
    proto: Protocol,

    // Raw Socket
    tx: TransportSender,
    rx: TransportReceiver,

    // Flows
    current_flows: Arc<Mutex<Vec<Packets>>>,
    // TODO: à partager entre les différents protocoles ?
    sockets: Arc<Mutex<Vec<SocketSessions>>>,
}

struct SocketSessions {
    flowids: Vec<FlowId>,
    port: u16,
    keep_open: bool,
}

fn close_session(sockets: &Arc<Mutex<Vec<SocketSessions>>>, fid: &FlowId) {
    let mut sockets = sockets.lock().unwrap();
    for sessions in sockets.iter_mut() {
        if let Some(pos) = sessions.flowids.iter().position(|f| f == fid) {
            sessions.flowids.remove(pos);
            // TODO: si sockets vide et keep_open est false, retirer iptables
        } else {
            log::error!("Flow ID not found");
        }
    }

    // drop the socket if it is not used anymore
    sockets.retain(|s| s.keep_open || !s.flowids.is_empty());
}

impl Stage4 {
    pub fn new(proto: Protocol) -> Self {
        // Create an l3 raw socket using libpnet
        // TODO: utiliser IpNextHeaderProtocol::new(u8) pour éviter le match
        let ip_next_header_protocol = match proto {
            Protocol::TCP => IpNextHeaderProtocols::Tcp,
            Protocol::UDP => IpNextHeaderProtocols::Udp,
            Protocol::ICMP => IpNextHeaderProtocols::Icmp,
            _ => todo!("Handle error"),
        };

        let channel_type = TransportChannelType::Layer3(ip_next_header_protocol);

        let (tx, rx) =
            transport_channel(4096, channel_type).expect("Error when creating transport channel");

        let current_flows = Arc::new(Mutex::new(Vec::new()));
        let sockets = Arc::new(Mutex::new(Vec::new()));

        Stage4 {
            proto,
            tx,
            rx,
            current_flows,
            sockets,
        }
    }

    pub fn handle_packets(&mut self) {
        // Send and receive packets in this thread
        let mut rx_iter = ipv4_packet_iter(&mut self.rx);
        loop {
            let mut packet_to_send: Option<(Duration, FlowId)> = None;
            {
                let flows = self.current_flows.lock().unwrap();
                for f in flows.iter() {
                    assert!(!f.packets.is_empty());
                    // TODO: remove the clone
                    if f.directions[0] == PacketDirection::Forward
                        && (packet_to_send.is_none()
                            || packet_to_send.clone().unwrap().0 > f.timestamps[0])
                    {
                        let d = f.flow.get_data();
                        let fid = FlowId {
                            src_ip: d.src_ip,
                            dst_ip: d.dst_ip,
                            src_port: d.src_port,
                            dst_port: d.dst_port,
                        };
                        packet_to_send = Some((f.timestamps[0], fid));
                    }
                }
            }
            let received_data = match &packet_to_send {
                None => Some(rx_iter.next().expect("Network error")),
                Some((ts, _)) => {
                    let timeout =
                        ts.saturating_sub(SystemTime::now().duration_since(UNIX_EPOCH).unwrap());
                    if timeout.is_zero() {
                        None
                    } else {
                        log::trace!("Waiting for {:?}", timeout);
                        // seulement disponible sur Unix?
                        rx_iter.next_with_timeout(timeout).expect("Network error")
                    }
                }
            };

            // TODO: timeout sur les flux dont on n’a pas reçu de paquets depuis longtemps
            if let Some((recv_packet, addr)) = received_data {
                // We received a packet during our wait
                let recv_tcp_packet = pnet::packet::tcp::TcpPacket::new(recv_packet.payload())
                    .expect("Failed to parse received packet");

                // since this is a backward packet, we need to reverse source and destination
                let fid = FlowId {
                    dst_ip: recv_packet.get_source(),
                    src_ip: recv_packet.get_destination(),
                    dst_port: recv_tcp_packet.get_source(),
                    src_port: recv_tcp_packet.get_destination(),
                };
                let mut flows = self.current_flows.lock().unwrap();
                let flow_pos = flows.iter().position(|f| fid.is_compatible(&f.flow));
                if let Some(flow_pos) = flow_pos {
                    log::error!("Packet received: processed on port {}", fid.src_port);
                    let mut flow = &mut flows[flow_pos];
                    // look for the first backward packet. TODO: check for that particular packet
                    log::trace!("{:?}", flow.directions);
                    let pos = flow
                        .directions
                        .iter()
                        .position(|d| d == &PacketDirection::Backward)
                        .unwrap();
                    assert_eq!(pos, 0);
                    flow.directions.remove(pos);
                    flow.packets.remove(pos);
                    flow.timestamps.remove(pos);
                    if flow.directions.is_empty() {
                        flows.remove(flow_pos);
                        close_session(&self.sockets, &fid);
                    }
                } else {
                    log::trace!("Packet received: ignored {:?}", fid);
                }
                // Go back to searching for the next packet to send because it may have changed
            } else {
                // We need to send a packet
                let mut flows = self.current_flows.lock().unwrap();
                let (ts, fid) = packet_to_send.unwrap(); // always possible by construction
                                                         // TODO: enumerate plutôt
                let flow_pos = flows
                    .iter()
                    .position(|f| fid.is_compatible(&f.flow))
                    .expect("Need to send a packet in an unknown session");
                let mut flow = &mut flows[flow_pos];
                let pos = flow
                    .directions
                    .iter()
                    .position(|d| d == &PacketDirection::Forward)
                    .unwrap();
                assert_eq!(pos, 0); // it should be the first in the list
                let packet = flow.packets.remove(pos);
                flow.directions.remove(pos);
                flow.timestamps.remove(pos);

                // Get the expected time of arrival of the packet to know if we should wait before sending or receiving it

                let eth_packet = pnet::packet::ethernet::EthernetPacket::new(&packet.data).unwrap();
                let ipv4_packet =
                    pnet::packet::ipv4::Ipv4Packet::new(eth_packet.payload()).unwrap();

                match self
                    .tx
                    .send_to(&ipv4_packet, std::net::IpAddr::V4(fid.dst_ip))
                {
                    Ok(n) => assert_eq!(n, ipv4_packet.packet().len()), // Check if the whole packet was sent
                    Err(e) => panic!("failed to send packet: {}", e),
                }
                log::trace!("Packet sent from port {}", fid.src_port);

                if flow.directions.is_empty() {
                    // remove the flow ID from the socket list
                    flows.remove(flow_pos);
                    close_session(&self.sockets, &fid);
                }
            }
        }
    }

    pub fn start(&mut self, mut incoming_flows: Receiver<SeededData<Packets>>) {
        // TODO: vérifier s’il faut mettre un SeededData ici ou pas

        log::info!("stage4 started");
        // Create a thread to receive incoming flows and add them to the current_flows
        let mut current_flows = self.current_flows.clone();
        let mut sockets = self.sockets.clone();
        let builder = thread::Builder::new().name("Stage4-socket".into());
        let join_handle = builder
            .spawn(move || {
                // TODO: faire sa propre fonction
                while let Ok(flow) = incoming_flows.recv() {
                    log::trace!("Received a new flow: {:?}", flow.data.directions);

                    log::debug!(
                        "Currently {} ongoing flows",
                        current_flows.lock().unwrap().len() + 1
                    );

                    // bind the socket as soon as we know we will deal with it, before receiving any
                    // packet
                    if let Flow::TCP(tcp_flow) = &flow.data.flow {
                        // TODO: check with self.proto
                        let mut sockets = sockets.lock().unwrap();
                        let mut found = false;
                        for sessions in sockets.iter_mut() {
                            if sessions.port == tcp_flow.src_port {
                                sessions.flowids.push(FlowId {
                                    src_ip: tcp_flow.src_ip,
                                    dst_ip: tcp_flow.dst_ip,
                                    src_port: tcp_flow.src_port,
                                    dst_port: tcp_flow.dst_port,
                                });
                                found = true;
                                break;
                            }
                        }
                        if !found {
                            // The port is not currently open
                            log::debug!("Binding socket to {}:{}", tcp_flow.src_ip, tcp_flow.src_port);
                            let fid = FlowId {
                                src_ip: tcp_flow.src_ip,
                                dst_ip: tcp_flow.dst_ip,
                                src_port: tcp_flow.src_port,
                                dst_port: tcp_flow.dst_port,
                                    };
                            sockets.push(SocketSessions {
                                flowids: vec![fid],
                                port: tcp_flow.src_port,
                                keep_open: tcp_flow.src_port < 1024 });
                            // TODO: activer iptables pour tcp_flow.src_port
                        }
                    } else {
                        panic!("Only TCP is implemented");
                    }

                    current_flows.lock().unwrap().push(flow.data);
                }
            })
            .unwrap();

        // TODO: faire ça proprement
        thread::sleep(Duration::new(2, 0)); // wait a few seconds so current_flows is not empty when
                                            // "handle_packets" is called

        // Handle packets
        self.handle_packets();

        join_handle.join().unwrap();
    }
}
