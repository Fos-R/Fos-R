use crate::*;

use crossbeam_channel::Receiver;
use pnet::transport::{
    ipv4_packet_iter, transport_channel, TransportChannelType, TransportReceiver, TransportSender,
};
use pnet_packet::{ip::IpNextHeaderProtocols, Packet};
use std::sync::Mutex;
use std::time::Duration;

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
    // proto: Protocol,

    // Raw Socket
    tx: TransportSender,
    rx: TransportReceiver,

    // Flows
    current_flows: Arc<Mutex<Vec<Packets>>>,
    // TODO: à partager entre les différents protocoles ?
    sessions_per_port: Arc<Mutex<Vec<PortSessions>>>,
}

struct PortSessions {
    flowids: Vec<FlowId>,
    port: u16,
    keep_open: bool,
}

fn close_session(sessions_per_port: &Arc<Mutex<Vec<PortSessions>>>, fid: &FlowId) {
    log::debug!("Session is finished");
    let mut sessions_per_port = sessions_per_port.lock().unwrap();
    for sessions in sessions_per_port.iter_mut() {
        if sessions.port == fid.src_port {
            if let Some(pos) = sessions.flowids.iter().position(|f| f == fid) {
                sessions.flowids.remove(pos);
                if sessions.flowids.is_empty() && !sessions.keep_open {
                    log::debug!("Ip tables removed for {}", fid.src_port);
                    let ipt = iptables::new(false).unwrap();
                    ipt.delete(
                        "mangle",
                        "OUTPUT",
                        &format!(
                            "-j DROP --match ttl --ttl-eq 64 -p tcp --source-port {}",
                            fid.src_port
                        ),
                    )
                    .unwrap();
                    ipt.delete(
                        "mangle",
                        "OUTPUT",
                        &format!("-j TTL --ttl-dec 1 -p tcp --source-port {}", fid.src_port),
                    )
                    .unwrap();
                }

                // TODO: si sessions_per_port vide et keep_open est false, retirer iptables
            } else {
                log::error!("Flow ID not found");
            }
        }
    }

    // drop the socket if it is not used anymore
    sessions_per_port.retain(|s| s.keep_open || !s.flowids.is_empty());
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
        let sessions_per_port = Arc::new(Mutex::new(Vec::new()));

        Stage4 {
            // proto,
            tx,
            rx,
            current_flows,
            sessions_per_port,
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
                        packet_to_send = Some((f.timestamps[0], f.flow.get_flow_id()));
                    }
                }
            }
            let received_data = match &packet_to_send {
                None => {
                    // log::trace!("No next packet to send");
                    Some(rx_iter.next().expect("Network error"))
                }
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
                };
                // TODO: check if taint is present
                let mut flows = self.current_flows.lock().unwrap();
                let flow_pos = flows.iter().position(|f| fid.is_compatible(&f.flow));
                if let Some(flow_pos) = flow_pos {
                    log::debug!("Packet received: processed on port {}", fid.src_port);
                    let flow = &mut flows[flow_pos];
                    // look for the first backward packet. TODO: check for that particular packet
                    log::trace!("{:?}", flow.directions);
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
                        close_session(&self.sessions_per_port, &fid);
                    }
                    // } else {
                    //     log::trace!("Packet received: ignored {:?}", fid);
                }
                // Go back to searching for the next packet to send because it may have changed
            } else {
                // We need to send a packet
                let mut flows = self.current_flows.lock().unwrap();
                let (_, fid) = packet_to_send.unwrap(); // always possible by construction
                                                        // TODO: enumerate plutôt
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
                let packet = flow.packets.remove(pos);
                flow.directions.remove(pos);
                flow.timestamps.remove(pos);

                // Get the expected time of arrival of the packet to know if we should wait before sending or receiving it

                let eth_packet = pnet::packet::ethernet::EthernetPacket::new(&packet.data).unwrap();
                let ipv4_packet =
                    pnet::packet::ipv4::Ipv4Packet::new(eth_packet.payload()).unwrap();

                log::trace!("Send to {:?}", fid);

                match self
                    .tx
                    .send_to(&ipv4_packet, std::net::IpAddr::V4(fid.dst_ip))
                {
                    Ok(n) => assert_eq!(n, ipv4_packet.packet().len()), // Check if the whole packet was sent
                    Err(e) => log::error!("failed to send packet: {}", e),
                }
                log::trace!("Packet sent from port {}", fid.src_port);

                if flow.directions.is_empty() {
                    // remove the flow ID from the socket list
                    flows.remove(flow_pos);
                    close_session(&self.sessions_per_port, &fid);
                }
            }
        }
    }

    pub fn start(&mut self, incoming_flows: Receiver<SeededData<Packets>>) {
        // TODO: vérifier s’il faut mettre un SeededData ici ou pas

        log::debug!("stage4 started");
        // Create a thread to receive incoming flows and add them to the current_flows
        let current_flows = self.current_flows.clone();
        let sessions_per_port = self.sessions_per_port.clone();
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
                    let mut sessions_per_port = sessions_per_port.lock().unwrap();
                    let mut found = false;
                    let fid = flow.data.flow.get_flow_id();
                    for sessions in sessions_per_port.iter_mut() {
                        if sessions.port == fid.src_port {
                            sessions.flowids.push(fid.clone());
                            found = true;
                            break;
                        }
                    }
                    // TODO use "local_port_available" to verify if the port is already used or not
                    if !found {
                        // TODO: vérifier si le port n’est pas déjà ouvert par une autre
                        // application
                        // The port is not currently open
                        let fid = flow.data.flow.get_flow_id();
                        sessions_per_port.push(PortSessions {
                            flowids: vec![fid.clone()],
                            port: fid.src_port,
                            keep_open: fid.src_port < 1024, // keep "server" ports open
                        });
                        // TODO: name chain "fosr"?
                        // TODO: modifier la chaîne pour prendre en compte d’UDP
                        log::debug!("Ip tables created for {}", fid.src_port);
                        let ipt = iptables::new(false).unwrap();
                        ipt.append(
                            "mangle",
                            "OUTPUT",
                            &format!(
                                "-j DROP --match ttl --ttl-eq 64 -p tcp --source-port {}",
                                fid.src_port
                            ),
                        )
                        .unwrap();
                        ipt.append(
                            "mangle",
                            "OUTPUT",
                            &format!("-j TTL --ttl-dec 1 -p tcp --source-port {}", fid.src_port),
                        )
                        .unwrap();
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

// fn local_port_available(port: u16) -> bool {
//     TcpListener::bind(("127.0.0.1", port)).is_ok()
// }
