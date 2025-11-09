use crate::stage1::*;

use rand_distr::weighted::WeightedIndex;
use rand_distr::{Distribution, Normal};
use rand_pcg::Pcg32;
use serde::Deserialize;
use std::collections::HashMap;
use std::collections::HashSet;
use std::iter;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;
use chrono::Timelike;

#[derive(Debug, Clone, Default)]
/// This structure holds the flow that is being built. Since we cannot instance all the variables
/// at the same time, each variable is an Option
struct IntermediateVector {
    dst_port: Option<u16>,
    ttl_client: Option<u8>,
    ttl_server: Option<u8>,
    fwd_packets_count: Option<usize>,
    bwd_packets_count: Option<usize>,
    timestamp: Option<Duration>,
    proto: Option<Protocol>,
    tcp_flags: Option<TCPEndFlags>,
    src_ip : Option<Ipv4Addr>,
    dst_ip : Option<Ipv4Addr>,
}

impl From<IntermediateVector> for Flow {
    fn from(p: IntermediateVector) -> Self {
        let d = FlowData {
            src_ip: p.src_ip.unwrap(),
            dst_ip: p.dst_ip.unwrap(),
            src_port: 0,
            dst_port: p.dst_port.unwrap(),
            ttl_client: p.ttl_client.unwrap(),
            ttl_server: p.ttl_server.unwrap(),
            fwd_packets_count: p.fwd_packets_count.unwrap(),
            bwd_packets_count: p.bwd_packets_count.unwrap(),
            timestamp: p.timestamp.unwrap(),
        };
        // match p.proto.unwrap() {
        //     Protocol::TCP => Flow::TCP(d, p.tcp_flags.unwrap()),
        //     Protocol::UDP => Flow::UDP(d),
        //     Protocol::ICMP => Flow::ICMP(d),
        // }
        p.proto.unwrap().wrap(d)
    }
}

// impl PartiallyDefinedFlowData {
//     fn set_value(&mut self, rng: &mut impl RngCore, f: &Feature, index: usize) {
//         todo!()
//         // match f {
//         //     Feature::SrcIP(v) => self.src_ip = Some(v.0[index]),
//         //     Feature::DstIP(v) => self.dst_ip = Some(v.0[index]),
//         //     Feature::DstPt(v) => self.dst_port = Some(v[index]),
//         //     Feature::FwdPkt(v) => self.fwd_packets_count = Some(v.0[index].sample(rng) as usize),
//         //     Feature::BwdPkt(v) => self.bwd_packets_count = Some(v.0[index].sample(rng) as usize),
//         //     Feature::Duration(_) => (),
//         //     Feature::L4Proto(v) => self.proto = Some(v[0]),
//         //     Feature::Flags(_) => (),
//         //     _ => todo!(),
//         // }
//     }
// }

/// A node of the Bayesian network
#[derive(Debug, Clone)]
struct BayesianNetworkNode {
    index: usize, // overall index, unique across the several BNs
    ignored_during_generation: bool, // for nodes that are duplicated across BNs
    feature: Feature,
    cpt: Option<CPT>,    // TimeBin has no CPT
    parents: Vec<usize>, // indices in the Bayesian network’s nodes
    parents_cardinality: Vec<usize>, // the cardinality of each parents. Used to compute the index
                         // in the cpt
}

#[derive(Debug, Clone)]
#[allow(clippy::upper_case_acronyms)]
/// A list of application layer protocol
enum L7Proto {
    HTTP,
    HTTPS,
    SSH,
    DNS,
    DHCP,
    SMTP,
    Telnet,
    IMAPS,
    MQTT,
    CanonBjmp,
    KMS,
    MulticastDNS,
    NTP,
    Unknown, // TODO properly
             // TODO complete
}

impl L7Proto {
    /// Default destination port that is used if a configuration file does not override it
    fn get_default_port(&self) -> u16 {
        match self {
            L7Proto::HTTP => 80,
            L7Proto::HTTPS => 443,
            L7Proto::SSH => 22,
            L7Proto::DNS => 53,
            L7Proto::DHCP => 67,
            L7Proto::SMTP => 587,
            L7Proto::Telnet => 23,
            L7Proto::IMAPS => 993,
            L7Proto::MQTT => 1883,
            L7Proto::CanonBjmp => 8612,
            L7Proto::KMS => 1688,
            L7Proto::MulticastDNS => 5353,
            L7Proto::NTP => 123,
            L7Proto::Unknown => 9999,
            // _ => todo!()
        }
    }
}

// TODO: refaire proprement
impl From<String> for L7Proto {
    fn from(s: String) -> L7Proto {
        match s.as_str() {
            "HTTP" => L7Proto::HTTP,
            "HTTPS" => L7Proto::HTTPS,
            "SSH" => L7Proto::SSH,
            "DNS" => L7Proto::DNS,
            "DHCP" => L7Proto::DHCP,
            "SMTP" => L7Proto::SMTP,
            "Telnet" => L7Proto::Telnet,
            "IMAPS" => L7Proto::IMAPS,
            "MQTT" => L7Proto::MQTT,
            "Canon-bjmp" => L7Proto::CanonBjmp,
            "KMS" => L7Proto::KMS,
            "Multicast DNS" => L7Proto::MulticastDNS,
            "NTP" => L7Proto::NTP,
            _ => L7Proto::Unknown,
        }
    }
}

#[derive(Debug, Clone)]
/// The TCP end flags
enum TCPEndFlags {
    None,
    R,
    FAndNotR,
    NotFAndNotR,
}

#[derive(Debug, Clone)]
/// The set of random variables that can appear in a Bayesian network
enum Feature {
    // for each feature, we associate a domain
    TimeBin(usize), // cardinality only
    SrcIpRole(Vec<String>),
    DstIpRole(Vec<String>),
    SrcIp(Vec<Ipv4Addr>),     // the IP comes from the config
    DstIp(Vec<Ipv4Addr>),     // the IP comes from the config
    DstPt(Vec<u16>),          // the port comes from the config (must be chosen after the dest IP)
    FwdPkt(Vec<Normal<f64>>), // the exact number is sampled from a Gaussian distribution afterward
    BwdPkt(Vec<Normal<f64>>), // idem
    L7Proto(Vec<L7Proto>),
    L4Proto(Vec<Protocol>),
    EndFlags,
}

impl Feature {
    fn get_cardinality(&self) -> usize {
        match &self {
            Feature::SrcIpRole(v) | Feature::DstIpRole(v) => v.len(),
            Feature::SrcIp(v) | Feature::DstIp(v) => v.len(),
            Feature::DstPt(v) => v.len(),
            Feature::FwdPkt(v) | Feature::BwdPkt(v) => v.len(),
            Feature::L4Proto(v) => v.len(),
            Feature::L7Proto(v) => v.len(),
            Feature::EndFlags => 4, // TODO: déduire de TCPEndFlags
            Feature::TimeBin(card) => *card,
        }
    }
}

// impl From<Vec<String>> for Ipv4Vector {
//     fn from(v: Vec<String>) -> Ipv4Vector {
//         // ignore non-IPv4, like anonymised public IP addresses
//         Ipv4Vector(v.into_iter().flat_map(|s| s.parse()).collect())
//     }
// }

#[allow(clippy::upper_case_acronyms)]
/// A conditional probability table
type CPT = Vec<WeightedIndex<f64>>;

impl BayesianNetworkNode {
    /// Sample the value of one variable and update the vector with it
    fn sample_index(&self, rng: &mut impl RngCore, current: &[usize]) -> usize {
        let mut parents_index = 0;
        for (index, card) in self.parents.iter().zip(self.parents_cardinality.iter()) {
            parents_index = parents_index * card + current[*index]
        }
        match &self.cpt {
            None => panic!("Trying to sample a TimeBin"),
            Some(cpt) => cpt.get(parents_index).unwrap().sample(rng),
        }
    }
}

#[derive(Debug)]
/// A Bayesian network, which is simply a collection of nodes
struct BayesianNetwork {
    nodes: Vec<BayesianNetworkNode>,
}

impl BayesianNetwork {
    /// Sample a vector from the Bayesian network
    fn sample(
        &self,
        rng: &mut impl RngCore,
        discrete_vector: &mut Vec<usize>,
        output_vector: &mut IntermediateVector,
    ) {
        for v in self.nodes.iter() {
            if !v.ignored_during_generation {
                let i = v.sample_index(rng, discrete_vector);
                discrete_vector.push(i);
                match &v.feature {
                    Feature::SrcIpRole(_) => (),
                    Feature::DstIpRole(_) => (),
                    Feature::L7Proto(v) => output_vector.dst_port = Some(v[i].get_default_port()),
                    Feature::SrcIp(v) => todo!(),
                    Feature::DstIp(v) => todo!(),
                    Feature::DstPt(v) => todo!(),
                    Feature::FwdPkt(v) => todo!(),
                    Feature::BwdPkt(v) => todo!(),
                    Feature::L4Proto(v) => todo!(),
                    Feature::EndFlags => todo!(),
                    Feature::TimeBin(card) => todo!(),
                }
            }
        }
    }
}

// BIFXML format

#[derive(Deserialize, Debug)]
#[serde(rename_all = "UPPERCASE")]
// The root element
pub struct Bif {
    network: Network,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "UPPERCASE")]
pub struct Network {
    name: String,     // TODO paramétrer dans agrum
    property: String, // learning software
    variable: Vec<Variable>,
    definition: Vec<Definition>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "UPPERCASE")]
pub struct Variable {
    name: String,
    property: Vec<String>,
    outcome: Vec<String>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "UPPERCASE")]
pub struct Definition {
    #[serde(rename = "FOR")]
    variable: String,
    given: Option<Vec<String>>,
    table: String,
}

/// The model with all the data
pub struct BayesianModel {
    bn_common: BayesianNetwork,
    bn_tcp: BayesianNetwork,
    bn_udp: BayesianNetwork,
    bn_additional_data: AdditionalData,
}

/// Stage 1: generates flow descriptions
#[derive(Clone)]
#[allow(unused)]
pub struct BNGenerator {
    model: Arc<BayesianModel>,
    online: bool, // used to generate the TTL, either initial or at the capture point
}

#[derive(Deserialize, Debug, Clone)]
struct AdditionalData {
    s0_bin_count: usize,
    ttl: HashMap<String, u64>,
    TCP_out_pkt_gaussians: GaussianDistribs,
    TCP_in_pkt_gaussians: GaussianDistribs,
    UDP_out_pkt_gaussians: GaussianDistribs,
    UDP_in_pkt_gaussians: GaussianDistribs,
}

impl GaussianDistribs {
    fn to_normals(&self) -> Vec<Normal<f64>> {
        self.mu
            .iter()
            .zip(self.cov.iter())
            .map(|(mu, cov)| Normal::new(*mu, cov.sqrt()).unwrap())
            .collect()
    }
}

#[derive(Deserialize, Debug, Clone)]
struct GaussianDistribs {
    mu: Vec<f64>,
    cov: Vec<f64>,
}

// Used only for computing the topological order
struct TopologicalNode {
    parents: HashSet<String>,
    children: Vec<String>,
}

impl BayesianModel {
    pub fn load() -> BayesianModel {
        let bn_additional_data: AdditionalData = serde_json::from_str(include_str!(
            "../../default_models/bn/bn_additional_data.json"
        ))
        .unwrap();

        // The BIFXML Bayesian network is converted to a "BayesianNetwork"
        // let mut overall_index: usize = 0; // common index across the BNs
        // let mut name_to_index: HashMap<String, usize> = HashMap::new();
        let mut var_names: Vec<String> = vec![];

        // The BIFXML file is read
        let mut bif_common: Bif =
            serde_xml_rs::from_str(include_str!("../../default_models/bn/bn_common.bifxml"))
                .unwrap();
        log::info!("Loading common BN");
        let bn_common = bn_from_bif(bif_common, &mut var_names, &bn_additional_data, None);

        let mut bif_tcp: Bif =
            serde_xml_rs::from_str(include_str!("../../default_models/bn/bn_tcp.bifxml")).unwrap();
        log::info!("Loading TCP BN");
        let bn_tcp = bn_from_bif(
            bif_tcp,
            &mut var_names,
            &bn_additional_data,
            Some(Protocol::TCP),
        );

        let mut bif_udp: Bif =
            serde_xml_rs::from_str(include_str!("../../default_models/bn/bn_udp.bifxml")).unwrap();
        log::info!("Loading UDP BN");
        let bn_udp = bn_from_bif(
            bif_udp,
            &mut var_names,
            &bn_additional_data,
            Some(Protocol::UDP),
        );

        BayesianModel {
            bn_common,
            bn_tcp,
            bn_udp,
            bn_additional_data,
        }
    }
}

fn bn_from_bif(
    mut bn: Bif,
    var_names: &mut Vec<String>,
    bn_additional_data: &AdditionalData,
    proto: Option<Protocol>,
) -> BayesianNetwork {
    let mut processed_bn = BayesianNetwork { nodes: vec![] };

    // first, start computing the topological order
    let mut nodes: HashMap<String, TopologicalNode> = HashMap::new();
    let mut roots = vec![];

    let initial_var_names_len = var_names.len();

    for def in bn.network.definition.iter() {
        nodes.insert(
            def.variable.clone(),
            TopologicalNode {
                parents: HashSet::new(),
                children: vec![],
            },
        );
        if def.given.is_none() {
            roots.push(def.variable.clone());
        }
    }

    if let Some(p) = roots.iter().position(|s| s.as_str() == "Time") {
        roots.swap(p,0); // Time must be the first variable if present
    }

    for def in bn.network.definition.iter() {
        if let Some(given) = &def.given {
            for v in given.iter() {
                nodes
                    .get_mut(&def.variable)
                    .unwrap()
                    .parents
                    .insert(v.clone());
                nodes
                    .get_mut(v)
                    .unwrap()
                    .children
                    .push(def.variable.clone());
            }
        }
    }

    let mut topo_order: Vec<String> = vec![];

    // Kahn’s algorithm
    while let Some(v) = roots.pop() {
        let children = nodes.get(&v).unwrap().children.clone();
        for c in children {
            let parents = &mut nodes.get_mut(&c.clone()).unwrap().parents;
            if parents.remove(&v) && parents.is_empty() {
                roots.push(c.clone());
            }
        }
        topo_order.push(v);
    }

    let mut sorted_network: Network = Network {
        name: bn.network.name,
        property: bn.network.property,
        variable: vec![],
        definition: vec![],
    };

    for v in topo_order {
        for (index, var) in bn.network.variable.iter().enumerate() {
            if var.name == v {
                sorted_network.variable.push(var.clone());
                sorted_network
                    .definition
                    .push(bn.network.definition[index].clone());
            }
        }
    }

    bn.network = sorted_network;

    for (v, def) in bn.network.variable.into_iter().zip(bn.network.definition) {
        assert_eq!(v.name, def.variable); // we assume the order is the same between
        // <variable> and <definition>
        let ignored_during_generation = v.name.as_str() == "Time" || var_names.contains(&v.name);

        var_names.push(v.name.clone());
        // name_to_index.insert(v.name.clone(), overall_index);

        // parents, searching in other BN
        let global_parents: Vec<usize> = def
            .given
            .clone()
            .unwrap_or(vec![])
            .into_iter()
            .map(|v| var_names.iter_mut().position(|s| s.as_str() == &v).unwrap())
            .collect();
        // parents, searching in this BN only
        let local_parents: Vec<usize> = def
            .given
            .unwrap_or(vec![])
            .into_iter()
            .map(|v| var_names.iter_mut().rposition(|s| s.as_str() == &v).unwrap())
            .collect();

        let cpt: CPT = def
            .table
            .split_ascii_whitespace()
            .map(|s| s.parse::<f64>().unwrap())
            .collect::<Vec<_>>()
            .chunks(v.outcome.len())
            .map(|l| WeightedIndex::new(l).unwrap())
            .collect();

        println!("{}", def.variable);
        let feature = match v.name.as_str() {
            "Time" => Feature::TimeBin(bn_additional_data.s0_bin_count),
            "Src IP Role" => Feature::SrcIpRole(v.outcome),
            "Dst IP Role" => Feature::DstIpRole(v.outcome),
            "Applicative Proto" => {
                Feature::L7Proto(v.outcome.into_iter().map(|s| s.into()).collect())
            }
            "Cat Out Packet" => match proto {
                Some(Protocol::TCP) => {
                    Feature::FwdPkt(bn_additional_data.TCP_out_pkt_gaussians.to_normals())
                }
                Some(Protocol::UDP) => {
                    Feature::FwdPkt(bn_additional_data.UDP_out_pkt_gaussians.to_normals())
                }
                _ => unreachable!(),
            },
            "Cat In Packet" => match proto {
                Some(Protocol::TCP) => {
                    Feature::FwdPkt(bn_additional_data.TCP_in_pkt_gaussians.to_normals())
                }
                Some(Protocol::UDP) => {
                    Feature::FwdPkt(bn_additional_data.UDP_in_pkt_gaussians.to_normals())
                }
                _ => unreachable!(),
            },
            "End Flags" => Feature::EndFlags,
            _ => unreachable!(),
        };

        let parents_cardinality = local_parents
            .iter()
            .map(|p| {
                println!("Searching for {p:?}");
                processed_bn
                    .nodes
                    .get(*p - initial_var_names_len)
                    .expect("Variables in BIFXML not in topological order!")
                    .feature
                    .get_cardinality()
            })
            .collect();

        let cpt = if matches!(feature, Feature::TimeBin(_)) {
            None
        } else {
            Some(cpt)
        };
        let node = BayesianNetworkNode {
            index: var_names.len() - 1, // it was the last pushed name
            feature,
            parents: global_parents, // indices in the Bayesian network’s nodes
            parents_cardinality,
            cpt,
            ignored_during_generation,
        };
        processed_bn.nodes.push(node);
    }

    processed_bn
}

impl BNGenerator {
    pub fn new(model: Arc<BayesianModel>, online: bool) -> Self {
        // TODO: adapter le modèle à la config !
        BNGenerator { model, online }
    }
}

impl Stage1 for BNGenerator {
    /// Generates flows
    fn generate_flows(&self, ts: SeededData<TimePoint>) -> impl Iterator<Item = SeededData<Flow>> {
        let mut rng = Pcg32::seed_from_u64(ts.seed);
        let mut discrete_vector: Vec<usize> = vec![];
        discrete_vector.push((ts.data.date_time.num_seconds_from_midnight() as usize) / self.model.bn_additional_data.s0_bin_count);
        let mut domain_vector: IntermediateVector = IntermediateVector::default();
        domain_vector.timestamp = Some(ts.data.unix_time);
        self.model.bn_common.sample(&mut rng, &mut discrete_vector, &mut domain_vector);
        match domain_vector.proto {
            Some(Protocol::TCP) => self.model.bn_tcp.sample(&mut rng, &mut discrete_vector, &mut domain_vector),
            Some(Protocol::UDP) => self.model.bn_udp.sample(&mut rng, &mut discrete_vector, &mut domain_vector),
            _ => unreachable!(),
        }
        iter::once(SeededData {
            seed: rng.next_u64(),
            data: domain_vector.into(),
        })

        // iter::empty::<SeededData<Flow>>()
        // data.timestamp = Some(ts.data.unix_time); // TODO! use date_time
        // data.ttl_client = Some(self.config.get_default_ttl(&data.src_ip.unwrap()));
        // data.ttl_server = Some(self.config.get_default_ttl(&data.dst_ip.unwrap()));
        // iter::once(SeededData {
        //     seed: rng.next_u64(),
        //     data: data.into(),
        // })
    }
}
