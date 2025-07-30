use crate::structs::*;
use crossbeam_channel::Receiver;
use crossbeam_channel::Select;
use pnet::transport::{
    TransportChannelType, TransportReceiver, TransportSender, ipv4_packet_iter, transport_channel,
};
use pnet_packet::MutablePacket;
use pnet_packet::Packet;
use pnet_packet::ip::IpNextHeaderProtocol;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(all(any(target_os = "windows", target_os = "linux"), feature = "ebpf"))]
pub mod ebpf;
#[cfg(all(target_os = "linux", feature = "iptables"))]
pub mod iptables;

pub trait NetEnabler: Clone + std::marker::Send + 'static {
    fn is_packet_relevant(&self, flags: u8) -> bool;
    fn is_fast(&self) -> bool;
    fn close_session(&self, f: &FlowId);
    fn open_session(&self, f: &FlowId);
}

#[derive(Debug, Clone)]
pub struct DummyNetEnabler {}

impl NetEnabler for DummyNetEnabler {
    fn is_packet_relevant(&self, _: u8) -> bool {
        false
    }
    fn is_fast(&self) -> bool {
        false
    }
    fn close_session(&self, _: &FlowId) {}
    fn open_session(&self, _: &FlowId) {}
}

const INTERVAL_TIMEOUT_CHECKS_IN_SECS: u64 = 60;
const SESSION_TIMEOUT_IN_SECS: u64 = 30;

/// Handles sending and receiving packets for a given protocol.
///
/// This function continuously:
/// - Checks for session timeouts and prunes expired flows.
/// - Determines the next packet to send based on flow timestamps.
/// - Waits to receive an incoming packet with an appropriate timeout,
///   or sends the next packet if its scheduled time has arrived.
///
/// # Parameters
///
/// - `proto`: The protocol associated with these packets.
/// - `tx`: Transport sender channel used to send packets.
/// - `rx`: Transport receiver channel used to receive packets.
/// - `current_flows`: Shared list of active flows.
/// - `taint`: Flag indicating whether taint-checking is active.
fn handle_packets(
    s4net: impl NetEnabler,
    proto: Protocol,
    mut tx: TransportSender,
    mut rx: TransportReceiver,
    current_flows: Arc<Mutex<Vec<Packets>>>,
) {
    // Send and receive packets in this thread
    let mut rx_iter = ipv4_packet_iter(&mut rx);
    let mut next_timeout_check = SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
        + Duration::from_secs(INTERVAL_TIMEOUT_CHECKS_IN_SECS);
    loop {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        if now > next_timeout_check {
            // flows that should have ended for more than "SESSION_TIMEOUT_IN_SECS"
            // seconds ago are pruned
            let timeout = now - Duration::from_secs(SESSION_TIMEOUT_IN_SECS);
            let mut flows = current_flows.lock().unwrap();
            let len = flows.len();
            for p in flows.iter() {
                if p.timestamps.last().unwrap() > &timeout {
                    s4net.close_session(&p.flow.get_flow_id());
                }
            }
            flows.retain(|p| p.timestamps.last().unwrap() > &timeout);
            next_timeout_check = now + Duration::from_secs(INTERVAL_TIMEOUT_CHECKS_IN_SECS);
            if len - flows.len() > 0 {
                log::debug!("Session timeout: {} sessions closed", len - flows.len());
            }
        }
        let mut packet_to_send: Option<(Duration, FlowId)> = None;
        {
            let flows = current_flows.lock().unwrap();
            for f in flows.iter() {
                assert!(!f.packets.is_empty());
                if f.directions[0] == PacketDirection::Forward {
                    match &packet_to_send {
                        None => packet_to_send = Some((f.timestamps[0], f.flow.get_flow_id())),
                        Some(t) if t.0 > f.timestamps[0] => {
                            packet_to_send = Some((f.timestamps[0], f.flow.get_flow_id()))
                        }
                        _ => (),
                    }
                }
            }
        }

        #[cfg(target_os = "windows")]
        let received_data = match &packet_to_send {
            None => {
                // log::trace!("No next packet to send");
                // TODO: trouver une alternative à "next_with_timeout" pour Windows
                Some(rx_iter.next().expect("Network error"))
            }
            Some((ts, _)) => {
                let timeout = if s4net.is_fast() {
                    Duration::from_secs(0)
                } else {
                    ts.saturating_sub(now)
                };
                if timeout.is_zero() {
                    None
                } else {
                    // log::trace!("Waiting for {:?}", timeout);
                    // seulement disponible sur Unix?
                    Some(rx_iter.next().expect("Network error"))
                }
            }
        };

        #[cfg(target_os = "linux")]
        let received_data = match &packet_to_send {
            None => {
                // log::trace!("No next packet to send");
                // TODO: trouver une alternative à "next_with_timeout" pour Windows
                rx_iter
                    .next_with_timeout(Duration::from_secs(1))
                    .expect("Network error")
            }
            Some((ts, _)) => {
                let timeout = if s4net.is_fast() {
                    Duration::from_secs(0)
                } else {
                    ts.saturating_sub(now)
                };
                if timeout.is_zero() {
                    None
                } else {
                    // log::trace!("Waiting for {:?}", timeout);
                    // seulement disponible sur Unix?
                    rx_iter.next_with_timeout(timeout).expect("Network error")
                }
            }
        };

        if let Some((recv_packet, _addr)) = received_data {
            // We received a packet during our wait
            let recv_tcp_packet = pnet::packet::tcp::TcpPacket::new(recv_packet.payload())
                .expect("Failed to parse received packet");

            // since this is a backward packet, we need to reverse source and destination
            let fid = FlowId {
                dst_ip: recv_packet.get_source(),
                src_ip: recv_packet.get_destination(),
                dst_port: recv_tcp_packet.get_source(),
                src_port: recv_tcp_packet.get_destination(),
                protocol: proto,
            };
            if s4net.is_packet_relevant(recv_packet.get_flags()) {
                let mut flows = current_flows.lock().unwrap();
                let flow_pos = flows.iter().position(|f| fid.is_compatible(&f.flow));
                if let Some(flow_pos) = flow_pos {
                    log::debug!("Packet received: processed on port {}", fid.src_port);
                    let flow = &mut flows[flow_pos];
                    // look for the first backward packet. TODO: check for that particular packet
                    let pos = flow
                        .directions
                        .iter()
                        .position(|d| d == &PacketDirection::Backward)
                        .unwrap();
                    // assert_eq!(pos, 0);
                    flow.directions.remove(pos);
                    flow.packets.remove(pos);
                    flow.timestamps.remove(pos);

                    if flow.directions.is_empty() {
                        flows.remove(flow_pos);
                        s4net.close_session(&fid);
                    }
                } else {
                    log::trace!("Packet received: ignored {fid:?}");
                }
            }
            // Go back to searching for the next packet to send because it may have changed
        } else if let Some((_, fid)) = packet_to_send {
            // We need to send a packet
            let mut flows = current_flows.lock().unwrap();
            let flow_pos = flows
                .iter()
                .position(|f| fid.is_compatible(&f.flow))
                .expect("Need to send a packet in an unknown session");
            let flow = &mut flows[flow_pos];
            let pos = flow
                .directions
                .iter()
                .position(|d| d == &PacketDirection::Forward)
                .unwrap();
            // assert_eq!(pos, 0); // it should be the first in the list
            let mut packet = flow.packets.remove(pos);
            flow.directions.remove(pos);
            flow.timestamps.remove(pos);

            // Get the expected time of arrival of the packet to know if we should wait before sending or receiving it

            let mut eth_packet =
                pnet::packet::ethernet::MutableEthernetPacket::new(&mut packet.data).unwrap();
            let mut ipv4_packet =
                pnet::packet::ipv4::MutableIpv4Packet::new(eth_packet.payload_mut()).unwrap();

            if cfg!(target_os = "linux") && cfg!(feature = "iptables") {
                // iptables hack
                ipv4_packet.set_ttl(65);
            }

            log::trace!("Send to {fid:?}");

            let mut retry_count = 3;
            while retry_count > 0 {
                match tx.send_to(&ipv4_packet, std::net::IpAddr::V4(fid.dst_ip)) {
                    Ok(n) => {
                        assert_eq!(n, ipv4_packet.packet().len()); // Check if the whole packet was sent
                        log::trace!("Packet sent from port {}", fid.src_port);
                        retry_count = 0;
                    }
                    Err(e) => {
                        retry_count -= 1;
                        if retry_count > 0 {
                            log::error!("Failed to send packet: {e}. Retry.");
                        } else {
                            log::error!("Failed to send packet: {e}. Give up.");
                        }
                    }
                }
            }

            if flow.directions.is_empty() {
                // remove the flow ID from the socket list
                flows.remove(flow_pos);
                s4net.close_session(&fid);
            }
        } // else: no packet received, none to send
    }
}

/// Starts processing flows for Stage4.
///
/// This method sets up transport channels for each protocol, spawns threads to handle packet
/// sending/receiving, and listens on the provided receivers for incoming flows. Once a new flow is
/// detected, corresponding iptables firewall rules are set up.
///
/// # Parameters
///
/// - `incoming_flows`: A HashMap mapping each Protocol to its incoming packets channel.
pub fn start(s4net: impl NetEnabler, incoming_flows: HashMap<Protocol, Receiver<Packets>>) {
    log::trace!("Start S4");
    let mut sel = Select::new();
    let mut join_handles = Vec::new();
    let mut receivers = Vec::<Receiver<Packets>>::new();

    let current_flows = Arc::new(Mutex::new(Vec::new()));
    for (proto, rx_s4) in incoming_flows.into_iter() {
        let channel_type =
            TransportChannelType::Layer3(IpNextHeaderProtocol::new(proto.get_protocol_number()));
        let (rx, tx) = transport_channel(4096, channel_type)
            .map_err(|e| log::error!("Error {e}. Please retry with root privilege."))
            .unwrap();

        let builder = thread::Builder::new().name(format!("Stage4-{proto:?}"));
        let current_flows = current_flows.clone();
        let s4net = s4net.clone();

        join_handles.push(
            builder
                .spawn(move || {
                    handle_packets(s4net, proto, rx, tx, current_flows);
                })
                .unwrap(),
        );
        // transfer receivers to a list so they have an index
        receivers.push(rx_s4);
    }

    for rx in receivers.iter() {
        sel.recv(rx);
    }

    // Handle packets
    loop {
        let oper = sel.select();
        let index = oper.index();
        if let Ok(flow) = oper.recv(&receivers[index]) {
            log::debug!(
                "Currently {} ongoing flows",
                current_flows.lock().unwrap().len() + 1
            );

            // setup firewall rules as soon as we know we will deal with it, before receiving any
            // packet
            let fid = flow.flow.get_flow_id();
            // log::info!(
            //     "Next Fos-R flow: {}, {}, {}, {}, {}",
            //     fid.src_ip,
            //     fid.dst_ip,
            //     fid.src_port,
            //     fid.dst_port,
            //     flow.timestamps[0].as_millis()
            // );
            s4net.open_session(&fid);

            current_flows.lock().unwrap().push(flow);
        } else {
            break;
        }
    }
    for handle in join_handles.into_iter() {
        handle.join().unwrap();
    }
    log::trace!("S4 stops");
}
