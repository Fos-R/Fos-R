use super::NetEnabler;
use crate::structs::*;
use crate::stats::Stats;
use crossbeam_channel::Receiver;
use crossbeam_channel::RecvTimeoutError;
use crossbeam_channel::TryRecvError;
use pnet::transport::{TransportChannelType, TransportSender, transport_channel};
use pnet_packet::Packet as _;
use pnet_packet::ip::IpNextHeaderProtocol;
use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug)]
enum Elem {
    PacketToSend((Packet, Ipv4Addr, Duration)),
    CloseSession((FlowId, Duration)),
}

impl Elem {
    fn get_duration(&self) -> &Duration {
        match &self {
            Elem::PacketToSend((_, _, d)) => d,
            Elem::CloseSession((_, d)) => d,
        }
    }
}

impl Ord for Elem {
    fn cmp(&self, other: &Self) -> Ordering {
        // a > b if a is before b (binary heap is a max heap)
        other.get_duration().cmp(self.get_duration())
    }
}

impl PartialOrd for Elem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Elem {
    fn eq(&self, other: &Self) -> bool {
        self.get_duration() == other.get_duration() // should be enough…
    }
}

impl Eq for Elem {}

fn add_flow_to_heap(s4net: &impl NetEnabler, flow: Packets, heap: &mut BinaryHeap<Elem>) {
    let fid = flow.flow.get_flow_id();
    for (index, p) in flow.packets.into_iter().enumerate() {
        if flow.directions[index] == PacketDirection::Forward {
            // we add them is descending order, which helps the push complexity
            heap.push(Elem::PacketToSend((
                p,
                flow.flow.get_data().dst_ip,
                flow.timestamps[index],
            )));
            // log::trace!("{:?}", flow.timestamps[index]);
            // log::trace!("New packet in the heap");
        }
    }
    heap.push(Elem::CloseSession((
        fid,
        *flow.timestamps.last().unwrap() + Duration::from_secs(1),
    ))); // close the session one second after the last packet of the communication

    // set up the session as soon as possible
    s4net.open_session(&fid);
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
    stats: Arc<Stats>,
    rx_s4: Receiver<Packets>,
) {
    log::info!("Start injection tx");
    let mut heap: BinaryHeap<Elem> = BinaryHeap::with_capacity(10000);
    // Send and receive packets in this thread
    let mut last_sent: Option<Duration> = None;
    loop {
        loop {
            // check for new flows, but do not lose time if there is none
            match rx_s4.try_recv() {
                Ok(flow) => {
                    // log::trace!("New flow in try_recv");
                    add_flow_to_heap(&s4net, flow, &mut heap);
                }
                Err(TryRecvError::Empty) => break, // proceed to send a packet
                Err(TryRecvError::Disconnected) if heap.is_empty() => {
                    return;
                } // stop the thread
                _ => break,                        // disconnected, but still some message to send
            }
        }

        if let Some(timestamp) = heap.peek().map(Elem::get_duration) {
            // we have to wait before sending the message. Wait a new message meanwhile

            let waiting_duration =
                timestamp.saturating_sub(SystemTime::now().duration_since(UNIX_EPOCH).unwrap());

            // log::warn!("Waiting duration: {waiting_duration:?}");

            if !timestamp.is_zero() {
                match rx_s4.recv_timeout(waiting_duration) {
                    Ok(flow) => {
                        // log::trace!("New flow in recv_timeout");
                        add_flow_to_heap(&s4net, flow, &mut heap);
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

            // we waited long enough to send the packet and we didn’t receive any other packet
            // meanwhile: we can send it.
            assert!(!heap.is_empty());
            let elem = heap.pop().unwrap(); // we know it exists
            match elem {
                Elem::CloseSession((fid, _)) => s4net.close_session(&fid),
                Elem::PacketToSend((packet, dst_ip, d)) => {
                    if let Some(last_sent) = last_sent {
                        // log::debug!("{d:?} {last_sent:?}");
                        assert!(d >= last_sent);
                    }
                    last_sent = Some(d);
                    // TODO: le stage 3 pourrait mieux préparer ses données…
                    let eth_packet =
                        pnet::packet::ethernet::EthernetPacket::new(&packet.data).unwrap();
                    let ipv4_packet =
                        pnet::packet::ipv4::Ipv4Packet::new(eth_packet.payload()).unwrap();

                    // log::trace!("Send to {dst_ip:?}");

                    let mut retry_count = 3;
                    while retry_count > 0 {
                        // only send the IP part (the network layer is handled by the kernel)
                        match tx.send_to(&ipv4_packet, std::net::IpAddr::V4(dst_ip)) {
                            Ok(n) => {
                                assert_eq!(n, ipv4_packet.packet().len()); // Check if the whole packet was sent
                                // log::trace!("Packet sent");
                                stats.packet_sent();
                                break;
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
            }
        } else {
            // we have nothing to do... so we can only wait
            // for a new flow in a blocking way
            match rx_s4.recv() {
                Ok(flow) => {
                    // log::trace!("New flow in recv");
                    add_flow_to_heap(&s4net, flow, &mut heap);
                }
                Err(_) => {
                    assert!(heap.is_empty());
                    return;
                } // no more packet to send, ever
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
pub fn start_fast(
    s4net: impl NetEnabler,
    incoming_flows: HashMap<Protocol, Receiver<Packets>>,
    stats: Arc<Stats>,
) {
    log::trace!("Start injection");
    let mut join_handles = Vec::new();
    for (proto, rx_s4) in incoming_flows.into_iter() {
        // for each transport protocol, create a new raw socket
        // the raw socket listens to all the interfaces
        let channel_type =
            TransportChannelType::Layer3(IpNextHeaderProtocol::new(proto.get_protocol_number()));
        #[allow(unused_mut)]
        let (mut tx, _) = transport_channel(4096, channel_type)
            .map_err(|e| log::error!("Error {e}. Please retry with root privilege."))
            .unwrap();

        // iptables hack
        s4net.get_ttl().map(|ttl| tx.set_ttl(ttl).unwrap());

        let builder = thread::Builder::new().name(format!("Stage4-{proto:?}"));
        let stats = stats.clone();
        let s4net = s4net.clone();
        join_handles.push(
            builder
                .spawn(move || {
                    send_packets(s4net, tx, stats, rx_s4);
                })
                .unwrap(),
        );
        // transfer receivers to a list so they have an index
        // receivers.push(rx_s4);
    }

    for handle in join_handles.into_iter() {
        // wait for the TX threads to finish
        handle.join().unwrap();
    }
    log::trace!("Injection stops");
}
