use crate::stage2::*;
use rand_core::*;
use rand_pcg::Pcg32;
use std::ffi::OsStr;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

pub struct AutomataLibrary {
    // TODO: map port -> automata
    cons_tcp_automata: Vec<automaton::CrossProductTimedAutomaton<TCPEdgeTuple>>,
    cons_udp_automata: Vec<automaton::CrossProductTimedAutomaton<UDPEdgeTuple>>,
    cons_icmp_automata: Vec<automaton::CrossProductTimedAutomaton<ICMPEdgeTuple>>,

    tcp_automata: Vec<automaton::TimedAutomaton<TCPEdgeTuple>>,
    udp_automata: Vec<automaton::TimedAutomaton<UDPEdgeTuple>>,
    icmp_automata: Vec<automaton::TimedAutomaton<ICMPEdgeTuple>>,
}

impl Default for AutomataLibrary {
    #[cfg(debug_assertions)]
    fn default() -> Self {
        let mut lib = AutomataLibrary {
            cons_tcp_automata: vec![],
            cons_udp_automata: vec![],
            cons_icmp_automata: vec![],

            tcp_automata: vec![],
            udp_automata: vec![],
            icmp_automata: vec![],
        };
        lib.import_from_str(include_str!("../../default_models/automata/mqtt.json"))
            .unwrap();
        lib.import_from_str(include_str!("../../default_models/automata/smtp.json"))
            .unwrap();
        lib.import_from_str(include_str!("../../default_models/automata/ssh.json"))
            .unwrap();
        lib.import_from_str(include_str!("../../default_models/automata/https.json"))
            .unwrap();
        lib.import_from_str(include_str!("../../default_models/automata/dns.json"))
            .unwrap();
        lib.import_from_str(include_str!("../../default_models/automata/ntp.json"))
            .unwrap();
        lib
    }

    #[cfg(not(debug_assertions))]
    fn default() -> Self {
        let mut lib = AutomataLibrary {
            cons_tcp_automata: vec![],
            cons_udp_automata: vec![],
            cons_icmp_automata: vec![],

            tcp_automata: vec![],
            udp_automata: vec![],
            icmp_automata: vec![],
        };
        lib.import_from_str(
            &String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                "default_models/automata/mqtt.json",
                19
            ))
            .unwrap(),
        )
        .unwrap();
        lib.import_from_str(
            &String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                "default_models/automata/smtp.json",
                19
            ))
            .unwrap(),
        )
        .unwrap();
        lib.import_from_str(
            &String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                "default_models/automata/https.json",
                19
            ))
            .unwrap(),
        )
        .unwrap();
        lib.import_from_str(
            &String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                "default_models/automata/ssh.json",
                19
            ))
            .unwrap(),
        )
        .unwrap();
        lib.import_from_str(
            &String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                "default_models/automata/dns.json",
                19
            ))
            .unwrap(),
        )
        .unwrap();
        lib.import_from_str(
            &String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                "default_models/automata/ntp.json",
                19
            ))
            .unwrap(),
        )
        .unwrap();
        lib
    }
}

impl AutomataLibrary {
    pub fn from_dir(directory_name: &str) -> Self {
        let mut nb = 0;
        let mut lib = AutomataLibrary {
            cons_tcp_automata: vec![],
            cons_udp_automata: vec![],
            cons_icmp_automata: vec![],

            tcp_automata: vec![],
            udp_automata: vec![],
            icmp_automata: vec![],
        };

        let paths = fs::read_dir(directory_name).expect("Cannot read directory");
        for p in paths {
            let p = p.expect("Cannot open path").path();
            if !p.is_dir() && p.extension() == Some(OsStr::new("json")) {
                match lib.import_from_file(&p) {
                    Ok(()) => {
                        log::debug!("Automaton {:?} is loaded", p.file_name().unwrap());
                        nb += 1
                    }
                    Err(s) => log::error!(
                        "Could not load automaton {:?} ({})",
                        p.file_name().unwrap(),
                        s
                    ),
                }
            }
        }
        log::info!("{nb} automata have been loaded");
        lib
    }

    pub fn import_from_file(&mut self, filename: &PathBuf) -> std::io::Result<()> {
        let string = fs::read_to_string(filename)?;
        self.import_from_str(&string)
    }

    pub fn import_from_str(&mut self, string: &str) -> std::io::Result<()> {
        let a: automaton::JsonAutomaton = serde_json::from_str(string)?;
        match a.protocol {
            Protocol::TCP => {
                let a = automaton::TimedAutomaton::<TCPEdgeTuple>::import_timed_automaton(
                    a,
                    parse_tcp_symbol,
                );
                log::debug!("Import TCP {a}");
                self.tcp_automata.push(a.clone());
                self.cons_tcp_automata.push(a.into());
            }
            Protocol::UDP => {
                let a = automaton::TimedAutomaton::<UDPEdgeTuple>::import_timed_automaton(
                    a,
                    parse_udp_symbol,
                );
                log::debug!("Import UDP {a}");
                self.udp_automata.push(a.clone());
                self.cons_udp_automata.push(a.into());
            }
            Protocol::ICMP => {
                let a = automaton::TimedAutomaton::<ICMPEdgeTuple>::import_timed_automaton(
                    a,
                    parse_icmp_symbol,
                );
                log::debug!("Import ICMP {a}");
                self.icmp_automata.push(a.clone());
                self.cons_icmp_automata.push(a.into());
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct TadamGenerator {
    lib: Arc<AutomataLibrary>,
}

impl TadamGenerator {
    pub fn new(lib: Arc<AutomataLibrary>) -> Self {
        TadamGenerator { lib }
    }
}

fn update_packet_counts<U: PacketInfo>(packets_info: &mut [U], flow: &mut FlowData) {
    flow.fwd_packets_count = Some(
        packets_info
            .iter()
            .filter(|p| p.get_direction() == PacketDirection::Forward)
            .count(),
    );
    flow.bwd_packets_count = Some(
        packets_info
            .iter()
            .filter(|p| p.get_direction() == PacketDirection::Backward)
            .count(),
    );
}

#[allow(unused)]
impl Stage2 for TadamGenerator {
    fn generate_tcp_packets_info(
        &self,
        mut flow: SeededData<FlowData>,
    ) -> Option<SeededData<PacketsIR<TCPPacketInfo>>> {
        let mut rng = Pcg32::seed_from_u64(flow.seed);
        let packets_info = match (flow.data.fwd_packets_count, flow.data.bwd_packets_count) {
            (Some(_), Some(_)) => self
                .lib
                .cons_tcp_automata
                .iter()
                .find(|a| a.is_compatible_with(flow.data.dst_port))
                .map(|a| automaton::sample(&mut rng, a, &flow.data, create_tcp_header)),
            _ => self
                .lib
                .tcp_automata
                .iter()
                .find(|a| a.is_compatible_with(flow.data.dst_port))
                .map(|a| automaton::sample(&mut rng, a, &flow.data, create_tcp_header)),
        };

        if let Some(mut packets_info) = packets_info {
            update_packet_counts(&mut packets_info, &mut flow.data);

            Some(SeededData {
                seed: rng.next_u64(),
                data: PacketsIR::<TCPPacketInfo> {
                    packets_info,
                    flow: Flow::TCP(flow.data),
                },
            })
        } else {
            log::error!("No automaton for destination port {}", flow.data.dst_port);
            None
        }
    }

    fn generate_udp_packets_info(
        &self,
        mut flow: SeededData<FlowData>,
    ) -> Option<SeededData<PacketsIR<UDPPacketInfo>>> {
        let mut rng = Pcg32::seed_from_u64(flow.seed);
        let packets_info = match (flow.data.fwd_packets_count, flow.data.bwd_packets_count) {
            (Some(_), Some(_)) => self
                .lib
                .cons_udp_automata
                .iter()
                .find(|a| a.is_compatible_with(flow.data.dst_port))
                .map(|a| automaton::sample(&mut rng, a, &flow.data, create_udp_header)),
            _ => self
                .lib
                .udp_automata
                .iter()
                .find(|a| a.is_compatible_with(flow.data.dst_port))
                .map(|a| automaton::sample(&mut rng, a, &flow.data, create_udp_header)),
        };

        if let Some(mut packets_info) = packets_info {
            update_packet_counts(&mut packets_info, &mut flow.data);

            Some(SeededData {
                seed: rng.next_u64(),
                data: PacketsIR::<UDPPacketInfo> {
                    packets_info,
                    flow: Flow::UDP(flow.data),
                },
            })
        } else {
            log::error!("No automaton for destination port {}", flow.data.dst_port);
            None
        }
    }

    fn generate_icmp_packets_info(
        &self,
        flow: SeededData<FlowData>,
    ) -> Option<SeededData<PacketsIR<ICMPPacketInfo>>> {
        todo!()
    }
}
