use crate::structs::*;
use crossbeam_channel::Receiver;
use crossbeam_channel::Select;
use pnet::datalink;
use pnet::transport::{
    TransportChannelType, TransportReceiver, TransportSender, ipv4_packet_iter, transport_channel,
};
use pnet_packet::MutablePacket;
use pnet_packet::Packet;
use pnet_packet::ip::IpNextHeaderProtocol;
use std::collections::HashMap;
use std::process::Command;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Stage4 {
    // Params
    taint: bool,
    fast: bool,

    // Flows
    current_flows: Arc<Mutex<Vec<Packets>>>,

    // eBPF
    #[allow(dead_code)]
    #[cfg(any(target_os = "windows", target_os = "linux"))]
    ebpf: aya::Ebpf,
}

const INTERVAL_TIMEOUT_CHECKS_IN_SECS: u64 = 60;
const SESSION_TIMEOUT_IN_SECS: u64 = 30;

impl FlowId {
    /// Closes the current session via iptables rules in Linux.
    /// This function removes firewall rules created for the session.
    #[cfg(target_os = "linux")]
    fn close_session(&self) {
        log::debug!("Ip tables removed for {self:?}");
        let status = Command::new("iptables")
            .args([
                "-w",
                "-t",
                "mangle",
                "-D",
                "OUTPUT",
                "-j",
                "DROP",
                "--match",
                "ttl",
                "--ttl-eq",
                "64",
                "-p",
                &format!("{:?}", self.protocol),
                "--sport",
                &format!("{}", self.src_port),
                "--dport",
                &format!("{}", self.dst_port),
                "-s",
                &format!("{}", self.src_ip),
                "-d",
                &format!("{}", self.dst_ip),
            ])
            .status()
            .expect("failed to execute process");
        assert!(status.success());

        let status = Command::new("iptables")
            .args([
                "-w",
                "-t",
                "mangle",
                "-D",
                "OUTPUT",
                "-j",
                "TTL",
                "--ttl-dec",
                "1",
                "-p",
                &format!("{:?}", self.protocol),
                "--sport",
                &format!("{}", self.src_port),
                "--dport",
                &format!("{}", self.dst_port),
                "-s",
                &format!("{}", self.src_ip),
                "-d",
                &format!("{}", self.dst_ip),
            ])
            .status()
            .expect("failed to execute process");
        assert!(status.success());
    }

    /// Opens a session by creating iptables rules on Linux.
    /// Establishes firewall rules to monitor and control outgoing packets for this session.
    #[cfg(target_os = "linux")]
    fn open_session(&self) {
        // TODO: name chain "fosr"?
        // TODO: modifier la chaîne pour prendre en compte d’UDP
        log::debug!("Ip tables created for {}", self.src_port);
        let status = Command::new("iptables")
            .args([
                "-w",
                "-t",
                "mangle",
                "-A",
                "OUTPUT",
                "-j",
                "DROP",
                "--match",
                "ttl",
                "--ttl-eq",
                "64",
                "-p",
                &format!("{:?}", self.protocol),
                "--sport",
                &format!("{}", self.src_port),
                "--dport",
                &format!("{}", self.dst_port),
                "-s",
                &format!("{}", self.src_ip),
                "-d",
                &format!("{}", self.dst_ip),
            ])
            .status()
            .expect("failed to execute process");
        assert!(status.success());

        let status = Command::new("iptables")
            .args([
                "-w",
                "-t",
                "mangle",
                "-A",
                "OUTPUT",
                "-j",
                "TTL",
                "--ttl-dec",
                "1",
                "-p",
                &format!("{:?}", self.protocol),
                "--sport",
                &format!("{}", self.src_port),
                "--dport",
                &format!("{}", self.dst_port),
                "-s",
                &format!("{}", self.src_ip),
                "-d",
                &format!("{}", self.dst_ip),
            ])
            .status()
            .expect("failed to execute process");
        assert!(status.success());

        log::debug!("Ip tables created for {}", self.src_port);
    }

    #[cfg(target_os = "windows")]
    fn close_session(&self) {}

    #[cfg(target_os = "windows")]
    fn open_session(&self) {}
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
/// - `taint`: Flag indicating whether taint-checking is active.
fn handle_packets(
    proto: Protocol,
    mut tx: TransportSender,
    mut rx: TransportReceiver,
    current_flows: Arc<Mutex<Vec<Packets>>>,
    taint: bool,
    fast: bool,
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
                    p.flow.get_flow_id().close_session();
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
                let timeout = if fast {
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
                let timeout = if fast {
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
            if !taint || recv_packet.get_flags() & 0b100 > 0 {
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
                        fid.close_session();
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

            if cfg!(target_os = "linux") {
                // iptables hack
                ipv4_packet.set_ttl(65);
            }

            log::trace!("Send to {fid:?}");

            match tx.send_to(&ipv4_packet, std::net::IpAddr::V4(fid.dst_ip)) {
                Ok(n) => assert_eq!(n, ipv4_packet.packet().len()), // Check if the whole packet was sent
                Err(e) => log::error!(
                    "failed to send packet: {}, length: {}",
                    e,
                    ipv4_packet.packet().len()
                ),
            }
            log::trace!("Packet sent from port {}", fid.src_port);

            if flow.directions.is_empty() {
                // remove the flow ID from the socket list
                flows.remove(flow_pos);
                fid.close_session();
            }
        } // else: no packet received, none to send
    }
}

/// Load the ebpf XDP program, and attach it to each valid interface used by Fos-R.
///
/// # Parameters
///
/// - `local_interfaces`: List of used (by Fos-R) network interfaces.
#[cfg(any(target_os = "windows", target_os = "linux"))]
fn load_ebpf_program(local_interfaces: &[datalink::NetworkInterface]) -> aya::Ebpf {
    use aya::programs::{Xdp, XdpFlags};

    // Retrieve the stored eBPF program that where stored, at compilation, into the binary
    // This only hold a reference, the object is stored by aya (globaly), so no need to store it anywhere,
    // it will not be destroyed at the end of the function
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/fosr"
    )))
    .expect("Couldn't retrieve eBPF program");
    let program: &mut Xdp = ebpf
        .program_mut("fosr_ebpf")
        .expect("Failed to get mut reference of program")
        .try_into()
        .expect("Failed to get Xdp program reference");
    program.load().expect("Failed to load eBPF program");

    // Attach the program to each network interface
    for local_interface in local_interfaces {
        program.attach(&local_interface.name, XdpFlags::SKB_MODE)
            .expect("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE");
    }

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        log::warn!("failed to initialize eBPF logger: {e}");
    }

    ebpf
}

impl Stage4 {
    /// Creates a new Stage4 instance.
    ///
    /// # Parameters
    ///
    /// - `taint`: Boolean flag to enable or disable taint-based packet filtering.
    pub fn new(taint: bool, fast: bool, local_interfaces: &[datalink::NetworkInterface]) -> Self {
        log::info!("Stage4 created");

        Stage4 {
            taint,
            fast,
            current_flows: Arc::new(Mutex::new(Vec::new())),
            #[cfg(any(target_os = "windows", target_os = "linux"))]
            ebpf: load_ebpf_program(local_interfaces),
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
    pub fn start(&mut self, incoming_flows: HashMap<Protocol, Receiver<Packets>>) {
        log::trace!("Start S4");
        let mut sel = Select::new();
        let mut join_handles = Vec::new();
        let mut receivers = Vec::<Receiver<Packets>>::new();
        let taint = self.taint;
        let fast = self.fast;

        for (proto, rx_s4) in incoming_flows.into_iter() {
            let channel_type = TransportChannelType::Layer3(IpNextHeaderProtocol::new(
                proto.get_protocol_number(),
            ));
            let (rx, tx) = transport_channel(4096, channel_type)
                .map_err(|e| log::error!("Error {e}. Please retry with root privilege."))
                .unwrap();

            let builder = thread::Builder::new().name(format!("Stage4-{proto:?}"));
            let current_flows = self.current_flows.clone();

            join_handles.push(
                builder
                    .spawn(move || {
                        handle_packets(proto, rx, tx, current_flows, taint, fast);
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
                    self.current_flows.lock().unwrap().len() + 1
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
                fid.open_session();

                self.current_flows.lock().unwrap().push(flow);
            } else {
                break;
            }
        }
        for handle in join_handles.into_iter() {
            handle.join().unwrap();
        }
        log::trace!("S4 stops");
    }
}
