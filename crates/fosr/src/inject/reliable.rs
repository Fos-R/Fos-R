use super::NetEnabler;
use crate::structs::*;
use crate::stats::Stats;
use crossbeam_channel::Receiver;
use crossbeam_channel::RecvTimeoutError;
use crossbeam_channel::TryRecvError;
use pnet::transport::{
    TransportChannelType, TransportReceiver, TransportSender, ipv4_packet_iter, transport_channel,
};
use pnet_packet::Packet;
use pnet_packet::ip::IpNextHeaderProtocol;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

const INTERVAL_TIMEOUT_CHECKS_IN_SECS: u64 = 15; // when to check for timeouts
const SESSION_TIMEOUT_IN_SECS: u64 = 10; // minimum amount of time after the theoretical last
// timestamp before we can dismiss a flow

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
#[cfg(feature = "net_injection")]
fn receive_packets(
    s4net: impl NetEnabler,
    proto: Protocol,
    mut rx: TransportReceiver,
    current_flows: Arc<Mutex<Vec<Packets>>>,
    stats: Arc<Stats>,
) {
    // Send and receive packets in this thread
    log::info!("Start injection rx");
    let mut rx_iter = ipv4_packet_iter(&mut rx);
    loop {
        let (recv_packet, _) = rx_iter.next().expect("Network error");

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
            stats.packet_received(); // only count the Fos-R packets
            // log::warn!("Waiting for current_flows…");
            let mut flows = current_flows.lock().unwrap();
            // log::warn!("Got current flows");
            // log::trace!("{} ongoing flows", flows.len());
            let flow_pos = flows.iter().position(|f| {
                // log::trace!("Incoming packet. Checking {fid:?} with {:?}", f.flow);
                fid.is_compatible(&f.flow)
            });
            if let Some(flow_pos) = flow_pos {
                // log::debug!("Packet received: processed on port {}", fid.src_port);
                let flow = &mut flows[flow_pos];
                // look for the first backward packet. TODO: check for that particular packet
                // in case of inversion
                let pos = flow
                    .directions
                    .iter()
                    .position(|d| d == &PacketDirection::Backward);
                if let Some(pos) = pos {
                    flow.directions.remove(pos);
                    flow.packets.remove(pos);
                    flow.timestamps.remove(pos);
                    assert_eq!(flow.directions.len(), flow.packets.len());
                    assert_eq!(flow.directions.len(), flow.timestamps.len());
                    if flow.directions.is_empty() {
                        // the flow has been entirely consumed: we can reove it
                        flows.remove(flow_pos);
                        s4net.close_session(&fid);
                    }
                    assert!(flows.iter().all(|f| !f.directions.is_empty()));
                } else {
                    log::warn!("Packet ignored: flow was not expecting one ({fid:?})");
                    stats.packet_ignored();
                }
            } else {
                log::warn!("Packet ignored: no corresponding flow ({fid:?})");
                stats.packet_ignored();
            }
        }
    }
}

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
#[cfg(feature = "net_injection")]
fn send_packets(
    s4net: impl NetEnabler,
    mut tx: TransportSender,
    current_flows: Arc<Mutex<Vec<Packets>>>,
    stats: Arc<Stats>,
    rx_s4: Receiver<Packets>,
) {
    log::info!("Start injection tx");
    // Send and receive packets in this thread
    let mut next_timeout_check = SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
        + Duration::from_secs(INTERVAL_TIMEOUT_CHECKS_IN_SECS);
    loop {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        if now > next_timeout_check {
            // flows that should have ended for more than "SESSION_TIMEOUT_IN_SECS"
            // seconds ago are pruned
            let timeout = now - Duration::from_secs(SESSION_TIMEOUT_IN_SECS);
            let mut flows = current_flows.lock().unwrap();
            let len = flows.len(); // used to count how many flows have been closed early
            flows.retain(|p| {
                if p.timestamps.last().unwrap() > &timeout {
                    true // we keep this flow
                } else {
                    s4net.close_session(&p.flow.get_flow_id());
                    false // we discard it
                }
            });
            next_timeout_check = now + Duration::from_secs(INTERVAL_TIMEOUT_CHECKS_IN_SECS);
            if len - flows.len() > 0 {
                log::debug!("Session timeout: {} sessions closed", len - flows.len());
            }
        }

        loop {
            // check for new flows, but do not lose time if there is none
            match rx_s4.try_recv() {
                Ok(flow) => {
                    let fid = flow.flow.get_flow_id();
                    // set up the session as soon as possible
                    s4net.open_session(&fid);
                    current_flows.lock().unwrap().push(flow);
                }
                Err(TryRecvError::Empty) => break, // proceed to send a packet
                Err(TryRecvError::Disconnected) if current_flows.lock().unwrap().is_empty() => {
                    return;
                } // stop the thread
                _ => break,                        // disconnected, but still some message to send
            }
        }

        let duration_to_next_send: Option<Duration> = current_flows
            .lock()
            .unwrap()
            .iter()
            // for each flow, find the first forward packet and returns its timestamp
            .filter_map(|f| {
                f.directions
                    .iter()
                    .position(|d| d == &PacketDirection::Forward)
                    .map(|pos| f.timestamps[pos])
            })
            .min();

        if let Some(timestamp) = duration_to_next_send {
            // we have to wait before sending the message. Wait a new message meanwhile ; if it’s a new
            // packet, we have to check the next packet to send again as it may have changed

            let waiting_duration =
                timestamp.saturating_sub(SystemTime::now().duration_since(UNIX_EPOCH).unwrap());

            // log::warn!("Waiting duration: {waiting_duration:?}");

            if !timestamp.is_zero() {
                match rx_s4.recv_timeout(waiting_duration) {
                    Ok(flow) => {
                        let fid = flow.flow.get_flow_id();
                        // set up the session as soon as possible
                        s4net.open_session(&fid);

                        current_flows.lock().unwrap().push(flow);
                        continue; // we received a new flow while waiting: maybe its first packet needs to
                        // be send earlier that the current one
                    }
                    Err(RecvTimeoutError::Timeout) => (), // timeout: we can send the current one
                    Err(RecvTimeoutError::Disconnected) => thread::sleep(
                        timestamp
                            .saturating_sub(SystemTime::now().duration_since(UNIX_EPOCH).unwrap()),
                    ), // disconnected: we need to wait a bit more
                };
            }

            // we waited long enough to send the packet. We need to find it again and to verify
            // whether it’s the first one of the sequence (i.e., if we are not waiting for any
            // other packet)

            // we find the closest packet we can actually send
            let mut flows = current_flows.lock().unwrap();
            let next_sendable_packet: Option<(usize, &mut Packets)> = flows
                .iter_mut()
                .enumerate()
                .filter(|(_, f)| f.directions[0] == PacketDirection::Forward)
                .min_by_key(|x| x.1.timestamps[0]);

            // if should always exist at this point
            if let Some((flow_pos, flow)) = next_sendable_packet {
                let timestamp = flow.timestamps[0];
                let fid = flow.flow.get_flow_id();
                let waiting_duration =
                    timestamp.saturating_sub(SystemTime::now().duration_since(UNIX_EPOCH).unwrap());

                // the next sendable packet is not necessarily the one we waited for
                // check if it’s reasonable to sent it now
                // otherwise, go back at the beginning
                if waiting_duration < Duration::from_millis(3) {
                    let packet = flow.packets.remove(0);
                    flow.directions.remove(0);
                    flow.timestamps.remove(0);
                    assert_eq!(flow.directions.len(), flow.packets.len());
                    assert_eq!(flow.directions.len(), flow.timestamps.len());

                    if flow.directions.is_empty() {
                        // remove the flow ID from the socket list
                        flows.remove(flow_pos);
                        s4net.close_session(&fid);
                    }
                    // ensure there is no empty flow
                    assert!(flows.iter().all(|f| !f.directions.is_empty()));
                    drop(flows); // we release the mutex before sending the packet

                    let eth_packet =
                        pnet::packet::ethernet::EthernetPacket::new(&packet.data).unwrap();
                    let ipv4_packet =
                        pnet::packet::ipv4::Ipv4Packet::new(eth_packet.payload()).unwrap();

                    // log::trace!("Send to {fid:?}");

                    let mut retry_count = 3;
                    while retry_count > 0 {
                        // only send the IP part (the network layer is handled by the kernel)
                        match tx.send_to(&ipv4_packet, std::net::IpAddr::V4(fid.dst_ip)) {
                            Ok(n) => {
                                assert_eq!(n, ipv4_packet.packet().len()); // Check if the whole packet was sent
                                // log::trace!("Packet sent from port {}", fid.src_port);
                                stats.packet_sent();
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
                }
            } // if we received a new flow while waiting, directly go back to the start of the loop
        } else {
            // we have nothing to do... so we can only wait
            // to it in a blocking way
            match rx_s4.recv() {
                Ok(flow) => {
                    let fid = flow.flow.get_flow_id();
                    // set up the session as soon as possible
                    s4net.open_session(&fid);
                    current_flows.lock().unwrap().push(flow);
                }
                Err(_) => return, // no more packet to send, ever
            }
        }
    }
}

/// Starts processing flows for Stage4.
///
/// This method sets up transport channels for each protocol, spawns threads to handle packet
/// sending/receiving, and listens on the provided receivers for incoming flows.
///
/// # Parameters
///
/// - `s4net`: a network enabler that handles the session opening and closing.
/// - `incoming_flows`: A HashMap mapping each Protocol to its incoming packets channel.
/// - `stats`: an Arc to a shared statistics structure
#[cfg(feature = "net_injection")]
pub fn start_reliable(
    s4net: impl NetEnabler,
    incoming_flows: HashMap<Protocol, Receiver<Packets>>,
    stats: Arc<Stats>,
) {
    log::trace!("Start injection");
    // let mut sel = Select::new();
    let mut join_handles = Vec::new();
    // let mut receivers = Vec::<Receiver<Packets>>::new(); // a list of receivers, for when used with Select
    for (proto, rx_s4) in incoming_flows.into_iter() {
        // for each transport protocol, create a new raw socket
        // the raw socket listens to all the interfaces
        let channel_type =
            TransportChannelType::Layer3(IpNextHeaderProtocol::new(proto.get_protocol_number()));
        #[allow(unused_mut)]
        let (mut tx, rx) = transport_channel(4096, channel_type)
            .map_err(|e| log::error!("Error {e}. Please retry with root privilege."))
            .unwrap();
        let current_flows = Arc::new(Mutex::new(Vec::new())); // one per protocol

        // TODO: si "fast", pas besoin d’écouter ?
        // autre possibilité : on drain les backward
        {
            let builder = thread::Builder::new().name(format!("Stage4-{proto:?}-rx"));
            let current_flows = current_flows.clone();
            let stats = stats.clone();
            let s4net = s4net.clone();
            // each protocol is handled by a different thread
            // the packet receiver is *not* waited with a join, because it can hang forever
            // effectively, the thread is detached
            // join_handles.push(
            // TODO: il faut rajouter son join_handle, car sinon le processus peut terminer alors
            // qu’on doit encore attendre des paquets, ce qui causerait l’arrêt du module eBPF et
            // causerait des réponses du noyau à ces messages
            builder
                .spawn(move || {
                    receive_packets(s4net, proto, rx, current_flows, stats);
                })
                .unwrap();
            // );
        }

        {
            // iptables hack
            #[cfg(all(target_os = "linux", feature = "iptables"))]
            s4net.get_ttl().map(|ttl| tx.set_ttl(ttl).unwrap());

            let builder = thread::Builder::new().name(format!("Stage4-{proto:?}-tx"));
            let current_flows = current_flows.clone();
            let stats = stats.clone();
            let s4net = s4net.clone();
            join_handles.push(
                builder
                    .spawn(move || {
                        send_packets(s4net, tx, current_flows, stats, rx_s4);
                    })
                    .unwrap(),
            );
        }

        // transfer receivers to a list so they have an index
        // receivers.push(rx_s4);
    }

    for handle in join_handles.into_iter() {
        // wait for the TX threads to finish
        handle.join().unwrap();
    }
    log::trace!("Injection stops");
}
