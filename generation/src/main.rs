mod structs;
use crate::structs::*;
mod cmd;

mod tcp;
mod udp;
mod icmp;

mod stage0;
mod stage1;
mod stage2;
mod stage3;
mod stage4;

use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::thread;
use std::path::Path;
use std::sync::Arc;
use std::net::Ipv4Addr;
use std::env;

use clap::Parser;
use crossbeam_channel::bounded;
use pnet::{ipnetwork::IpNetwork, datalink};

const CHANNEL_SIZE: usize = 5; // TODO: increase
const STAGE1_COUNT: usize = 1; // TODO: mettre en variable. Mode online _ou_ mode "économe", un seul thread. Sinon, un nombre qui dépend des cœurs disponibles.
const STAGE2_COUNT: usize = 1;
const STAGE3_COUNT: usize = 1;
const TCP_PROTO: u8 = 6;
const UDP_PROTO: u8 = 17;
const ICMP_PROTO: u8 = 1;


// Stage 0 and pcap export have only one thread and stage 4 has 3 threads, one per transport protocol

fn main() {
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "info") // default log level: info
    }
    env_logger::init();

    let args = cmd::Args::parse();
    log::trace!("{:?}", &args);
    let (start_unix_time, flow_count, online, noise) =
        match args.command {
            cmd::Command::Offline { start_unix_time, flow_count, noise, .. } => (start_unix_time.map(Duration::from_secs), flow_count, false, noise),
            cmd::Command::Online { } => (None, -1, true, false),
        };
    let start_unix_time = start_unix_time.unwrap_or(SystemTime::now().duration_since(UNIX_EPOCH).unwrap());

    let seed = args.seed.unwrap_or(42); //rand::random() TODO: change for release
    log::trace!("Generating with seed {}",seed);

    let local_interfaces: Vec<Ipv4Addr> = 
        if online {
            // Extract all IPv4 local interfaces (except loopback)
            let extract_addr = |iface: datalink::NetworkInterface| iface.ips.into_iter().filter(IpNetwork::is_ipv4).map(|i| match i { IpNetwork::V4(data) => data.ip(), _ => panic!("Impossible") });
            let ifaces = datalink::interfaces().into_iter().flat_map(extract_addr).filter(|i| !i.is_loopback()).collect();
            log::trace!("IPv4 interfaces: {:?}", &ifaces);
            ifaces
        } else {
            vec![]
        };

    let mut threads = vec![];

    // All the channels
    let (tx_s0, rx_s1) = bounded::<SeededData<Duration>>(CHANNEL_SIZE);
    let (tx_s1, rx_s2) = bounded::<SeededData<Flow>>(CHANNEL_SIZE);
    let (tx_s2_tcp, rx_s3_tcp) = bounded::<SeededData<PacketsIR<tcp::TCPPacketInfo>>>(CHANNEL_SIZE);
    let (tx_s2_udp, _rx_s3_udp) = bounded::<SeededData<PacketsIR<udp::UDPPacketInfo>>>(CHANNEL_SIZE);
    let (tx_s2_icmp, _rx_s3_icmp) = bounded::<SeededData<PacketsIR<icmp::ICMPPacketInfo>>>(CHANNEL_SIZE);
    let (tx_s3_tcp, rx_s4_tcp) = bounded::<SeededData<Vec<Packet>>>(CHANNEL_SIZE);
    let (_tx_s3_udp, _rx_s4_udp) = bounded::<SeededData<Vec<Packet>>>(CHANNEL_SIZE);
    let (_tx_s3_icmp, _rx_s4_icmp) = bounded::<SeededData<Vec<Packet>>>(CHANNEL_SIZE);
    let (tx_pcap, rx_pcap) = bounded::<Vec<Packet>>(CHANNEL_SIZE);

    // STAGE 0
    let builder = thread::Builder::new()
        .name("Stage0".into());
    threads.push(builder.spawn(move || {
        log::trace!("Start S0");
        let time_distrib = stage0::import_time_distribution("");
        let s0 = stage0::Stage0::new(seed, time_distrib, start_unix_time, flow_count);
        for ts in s0 {
            log::trace!("S0 generates {:?}",ts);
            tx_s0.send(ts).unwrap();
        }
        log::trace!("S0 stops");
    }).unwrap());

    // STAGE 1
    let patterns = Arc::new(stage1::import_patterns(Path::new(&args.models).join("patterns.json").to_str().unwrap()).expect("Cannot load patterns"));
    for _ in 0..STAGE1_COUNT {
        let rx_s1 = rx_s1.clone();
        let tx_s1 = tx_s1.clone();
        let patterns = Arc::clone(&patterns);
        let local_interfaces = local_interfaces.clone();
        let builder = thread::Builder::new()
            .name("Stage1".into());
        threads.push(builder.spawn(move || {
            log::trace!("Start S1");
            let s1 = stage1::Stage1::new(patterns, online);
            while let Ok(ts) = rx_s1.recv() {
                let flows = s1.generate_flows(ts).into_iter();
                log::trace!("S1 generates {:?}", flows);
                if online { // only keep relevant flows
                    flows.filter(|f| {
                        let data = f.data.get_data();
                        local_interfaces.contains(&data.src_ip) || local_interfaces.contains(&data.dst_ip)
                    }).for_each(|f| tx_s1.send(f).unwrap());
                } else {
                    flows.for_each(|f| tx_s1.send(f).unwrap());
                }
            }
            log::trace!("S1 stops");
        }).unwrap());
    }
    drop(rx_s1);
    drop(tx_s1);

    // STAGE 2

    let automata_library = Arc::new(stage2::import_automata_from_dir(Path::new(&args.models).join("tas").to_str().unwrap()));
    for _ in 0..STAGE2_COUNT {
        let rx_s2 = rx_s2.clone();
        let tx_s2_tcp = tx_s2_tcp.clone();
        let tx_s2_udp = tx_s2_udp.clone();
        let tx_s2_icmp = tx_s2_icmp.clone();
        let automata_library = Arc::clone(&automata_library);
        let builder = thread::Builder::new()
            .name("Stage2".into());
        threads.push(builder.spawn(move || {
            log::trace!("Start S2");
            // Prepare stage 2 by loading the automata
            let mut s2 = stage2::Stage2::new(automata_library);
            while let Ok(flow) = rx_s2.recv() {
                log::trace!("S2 waits");
                log::trace!("S2 generates");
                match flow.data {
                    Flow::TCP(data) => {
                        tx_s2_tcp.send(s2.generate_tcp_packets_info(SeededData { seed : flow.seed, data })).unwrap();
                    }
                    Flow::UDP(data) => {
                        tx_s2_udp.send(s2.generate_udp_packets_info(SeededData { seed : flow.seed, data })).unwrap();
                    },
                    Flow::ICMP(data) => {
                        tx_s2_icmp.send(s2.generate_icmp_packets_info(SeededData { seed : flow.seed, data })).unwrap();
                    },
                }
            }
            log::trace!("S2 stops");
        }).unwrap());
    }
    drop(rx_s2);
    drop(tx_s2_tcp);
    drop(tx_s2_udp);
    drop(tx_s2_icmp);

    // STAGE 3

    for _ in 0..STAGE3_COUNT {
        let rx_s3_tcp = rx_s3_tcp.clone();
        let tx_s3_tcp = tx_s3_tcp.clone();
        let tx_pcap = tx_pcap.clone();
        let builder = thread::Builder::new()
            .name("Stage3-TCP".into());
        threads.push(builder.spawn(move || {
            // Prepare stage 3 for TCP
            log::trace!("Start S3");
            let s3 = stage3::Stage3::new(args.taint);
            while let Ok(headers) = rx_s3_tcp.recv() {
                log::trace!("S3 generates");
                let flow_packets = s3.generate_tcp_packets(headers);
                // dbg!(&flow_packets);
                if online {
                    tx_s3_tcp.send(flow_packets).unwrap();
                } else {
                    let mut noisy_flow = SeededData { seed: flow_packets.seed, data: flow_packets.data };
                    if noise { // insert noise
                        stage3::insert_noise(&mut noisy_flow);
                    }
                    tx_pcap.send(noisy_flow.data).unwrap();
                }
            }
            log::trace!("S3 stops");
        }).unwrap());
    }
    drop(rx_s3_tcp);
    drop(_rx_s3_udp);
    drop(_rx_s3_icmp);
    drop(tx_s3_tcp);
    drop(_tx_s3_udp);
    drop(_tx_s3_icmp);
    drop(tx_pcap);

    // PCAP EXPORT

    if let cmd::Command::Offline { outfile, .. } = &args.command {
        let outfile = outfile.clone();
        let builder = thread::Builder::new()
            .name("Pcap-export".into());
        threads.push(builder.spawn(move || {
            log::trace!("Start pcap export thread");
            let mut packets_record = vec![];
            while let Ok(mut packets) = rx_pcap.recv() {
                packets_record.append(&mut packets)
            }
            stage3::pcap_export(packets_record, &outfile).expect("Error during pcap export!");
        }).unwrap());
    }

    // STAGE 4 (online-mode only)

    if online {
        let builder = thread::Builder::new()
            .name("Stage4-TCP".into());
        threads.push(builder.spawn(move || {
            log::trace!("Start S4");
            let s4 = stage4::Stage4::new(TCP_PROTO);
            while let Ok(packets) = rx_s4_tcp.recv() {
                s4.send(packets)
            }
            log::trace!("S4 stops");
        }).unwrap());
    }

    for thread in threads.into_iter() {
        log::trace!("Waiting for thread {}", thread.thread().name().unwrap());
        thread.join().unwrap();
        log::trace!("Thread ended");
    }
}
