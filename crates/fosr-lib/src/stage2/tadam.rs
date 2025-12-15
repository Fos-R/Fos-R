use crate::models;
use crate::stage2::*;

// use indicatif::{ProgressBar, ProgressStyle};
use rand_core::*;
use rand_pcg::Pcg32;
use std::collections::HashMap;
use std::sync::Arc;

pub struct AutomataLibrary {
    // TODO: deux types d’automates TCP: ceux finissant par FIN et ceux finissant par RESET
    cons_tcp_automata: HashMap<L7Proto, automaton::CrossProductTimedAutomaton<TCPEdgeTuple>>,
    cons_udp_automata: HashMap<L7Proto, automaton::CrossProductTimedAutomaton<UDPEdgeTuple>>,
    cons_icmp_automata: HashMap<L7Proto, automaton::CrossProductTimedAutomaton<ICMPEdgeTuple>>,

    tcp_automata: HashMap<L7Proto, automaton::TimedAutomaton<TCPEdgeTuple>>,
    udp_automata: HashMap<L7Proto, automaton::TimedAutomaton<UDPEdgeTuple>>,
    icmp_automata: HashMap<L7Proto, automaton::TimedAutomaton<ICMPEdgeTuple>>,
}

impl AutomataLibrary {
    pub fn from_source(models: &models::ModelsSource) -> Result<Self, String> {
        let strings = models
            .get_automata()
            .map_err(|_| "Cannot open the automata files".to_string())?;
        let mut nb = 0;
        let mut lib = AutomataLibrary {
            cons_tcp_automata: HashMap::new(),
            cons_udp_automata: HashMap::new(),
            cons_icmp_automata: HashMap::new(),

            tcp_automata: HashMap::new(),
            udp_automata: HashMap::new(),
            icmp_automata: HashMap::new(),
        };

        // let paths = fs::read_dir(directory_name).expect("Cannot read directory");
        // let pb = ProgressBar::new(paths.count() as u64);
        // pb.set_style(
        //     ProgressStyle::with_template(
        //         "{spinner:.green} Automata initialization: {pos}/{len} {wide_bar}",
        //     )
        //     .unwrap(),
        // );
        for s in strings {
            match lib.import_from_str(&s) {
                Ok(proto) => {
                    log::debug!("Automaton {proto:?} is loaded");
                    nb += 1
                }
                Err(s) => log::error!("Could not load automaton ({})", s),
            }
            // pb.inc(1);
        }
        log::info!("{nb} automata have been loaded");
        Ok(lib)
    }

    pub fn import_from_str(&mut self, string: &str) -> Result<L7Proto, String> {
        let a: automaton::JsonAutomaton =
            serde_json::from_str(string).map_err(|_| "Import error".to_string())?;
        let l7proto = a.l7protocol;
        match a.protocol {
            Protocol::TCP => {
                let a = automaton::TimedAutomaton::<TCPEdgeTuple>::import_timed_automaton(
                    a,
                    parse_tcp_symbol,
                )?;
                log::debug!("Import TCP {a}");
                self.tcp_automata.insert(l7proto, a.clone());
                self.cons_tcp_automata.insert(l7proto, a.into());
            }
            Protocol::UDP => {
                let a = automaton::TimedAutomaton::<UDPEdgeTuple>::import_timed_automaton(
                    a,
                    parse_udp_symbol,
                )?;
                log::debug!("Import UDP {a}");
                self.udp_automata.insert(l7proto, a.clone());
                self.cons_udp_automata.insert(l7proto, a.into());
            }
            Protocol::ICMP => {
                let a = automaton::TimedAutomaton::<ICMPEdgeTuple>::import_timed_automaton(
                    a,
                    parse_icmp_symbol,
                )?;
                log::debug!("Import ICMP {a}");
                self.icmp_automata.insert(l7proto, a.clone());
                self.cons_icmp_automata.insert(l7proto, a.into());
            }
        }
        Ok(l7proto)
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
    flow.fwd_packets_count = packets_info
        .iter()
        .filter(|p| p.get_direction() == PacketDirection::Forward)
        .count();
    flow.bwd_packets_count = packets_info
        .iter()
        .filter(|p| p.get_direction() == PacketDirection::Backward)
        .count();
}

#[allow(unused)]
impl Stage2 for TadamGenerator {
    fn generate_tcp_packets_info(
        &self,
        mut flow: SeededData<FlowData>,
    ) -> Option<SeededData<PacketsIR<TCPPacketInfo>>> {
        let mut rng = Pcg32::seed_from_u64(flow.seed);
        let a = self.lib.cons_tcp_automata.get(&flow.data.l7_proto);

        // automata is found
        if let Some(a) = a {
            let mut packets_info = automaton::sample(&mut rng, a, &flow.data, create_tcp_header);

            update_packet_counts(&mut packets_info, &mut flow.data);

            Some(SeededData {
                seed: rng.next_u64(),
                data: PacketsIR::<TCPPacketInfo> {
                    packets_info,
                    flow: Flow::TCP(flow.data),
                },
            })
        } else {
            log::error!("No TCP automaton for service {:?}", flow.data.l7_proto);
            None
        }
    }

    fn generate_udp_packets_info(
        &self,
        mut flow: SeededData<FlowData>,
    ) -> Option<SeededData<PacketsIR<UDPPacketInfo>>> {
        let mut rng = Pcg32::seed_from_u64(flow.seed);
        let a = self.lib.cons_udp_automata.get(&flow.data.l7_proto);

        // automata is found
        if let Some(a) = a {
            let mut packets_info = automaton::sample(&mut rng, a, &flow.data, create_udp_header);

            update_packet_counts(&mut packets_info, &mut flow.data);

            Some(SeededData {
                seed: rng.next_u64(),
                data: PacketsIR::<UDPPacketInfo> {
                    packets_info,
                    flow: Flow::UDP(flow.data),
                },
            })
        } else {
            log::error!("No UDP automaton for service {:?}", flow.data.l7_proto);
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
