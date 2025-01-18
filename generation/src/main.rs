mod structs;
use crate::structs::*;
mod cmd;

mod tcp;
mod udp;
mod icmp;

mod stage0;
mod stage1;
use stage1::flowchronicle;
mod stage2;
use stage2::tadam;
mod stage3;
mod stage4;

use std::time::{Duration, Instant};
use std::thread;
use std::path::Path;
use std::sync::{Mutex, Arc};
use std::net::Ipv4Addr;
use std::env;
use std::collections::HashMap;

use clap::Parser;
use crossbeam_channel::bounded;
use pnet::{ipnetwork::IpNetwork, datalink};

const CHANNEL_SIZE: usize = 50; // TODO: increase
const STAGE1_COUNT: usize = 1; // TODO: mettre en variable. Mode online _ou_ mode "économe", un seul thread. Sinon, un nombre qui dépend des cœurs disponibles.
const STAGE2_COUNT: usize = 1;
const STAGE3_COUNT: usize = 1; // per protocol
const STAGE4_COUNT: usize = 1; // per protocol
// monitor threads with "top -H -p $(pgrep fosr)"

#[derive(Default)]
pub struct Stats {
    pub packets_counter: Mutex<u64>,
    pub bytes_counter: Mutex<u64>,
}

impl Stats {
    pub fn increase(&self, p: &Packets) {
        let mut pc = self.packets_counter.lock().unwrap();
        *pc += p.packets.len() as u64;
        let mut bc = self.bytes_counter.lock().unwrap();
        *bc += (p.flow.get_data().fwd_total_payload_length + p.flow.get_data().bwd_total_payload_length) as u64;
    }
}

fn main() {
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "info") // default log level: info
    }
    env_logger::init();
    let start_time = Instant::now();
    let stats = Arc::new(Stats::default());
    let running = Arc::new(Mutex::new(true)); // TODO: use std::sync::atomic instead

    let args = cmd::Args::parse();
    log::trace!("{:?}", &args);
    let online = matches!(args.command, cmd::Command::Online { });
    // let (online, noise) =
    //     match args.command {
    //         cmd::Command::Offline { noise, .. } => (false, noise),
    //         cmd::Command::Online { } => (true, false),
    //     };

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
    let mut gen_threads = vec![];

    // block to automatically drop channels before the joins
    {

        // Channels creation
        let (tx_s0, rx_s1) = bounded::<SeededData<Duration>>(CHANNEL_SIZE);
        let (tx_s1, rx_s2) = bounded::<SeededData<Flow>>(CHANNEL_SIZE);
        let (tx_s2_tcp, rx_s3_tcp) = bounded::<SeededData<PacketsIR<tcp::TCPPacketInfo>>>(CHANNEL_SIZE);
        let (tx_s2_udp, rx_s3_udp) = bounded::<SeededData<PacketsIR<udp::UDPPacketInfo>>>(CHANNEL_SIZE);
        let (tx_s2_icmp, rx_s3_icmp) = bounded::<SeededData<PacketsIR<icmp::ICMPPacketInfo>>>(CHANNEL_SIZE);
        let tx_s2 = stage2::S2Sender { tcp: tx_s2_tcp, udp: tx_s2_udp, icmp: tx_s2_icmp };

        let mut tx_s3 = HashMap::new();
        let mut rx_s4 = HashMap::new();
        for proto in Protocol::iter() {
            let mut tx_s3_hm = HashMap::new();
            for iface in local_interfaces.iter() {
                let (tx, rx) = bounded::<SeededData<Packets>>(CHANNEL_SIZE);
                tx_s3_hm.insert(*iface, tx);
                rx_s4.insert((*iface, proto), rx);
            }
            tx_s3.insert(proto, tx_s3_hm);
        }
        let (tx_s3_to_collector, rx_collector) = bounded::<Packets>(CHANNEL_SIZE);
        let (tx_collector, rx_pcap) = bounded::<Vec<Packet>>(CHANNEL_SIZE);

        // STAGE 0

        let s0 = Box::new(stage0::UniformGenerator::new(seed, online, 2, 100));
        let builder = thread::Builder::new().name("Stage0".into());
        gen_threads.push(builder.spawn(move || stage0::run(s0, tx_s0)).unwrap());

        // STAGE 1

        let patterns = Arc::new(flowchronicle::PatternSet::from_file(Path::new(&args.models).join("patterns.json").to_str().unwrap()).expect("Cannot load patterns"));
        for _ in 0..STAGE1_COUNT {
            let rx_s1 = rx_s1.clone();
            let tx_s1 = tx_s1.clone();
            let local_interfaces = local_interfaces.clone();
            let patterns = Arc::clone(&patterns);
            let builder = thread::Builder::new().name("Stage1".into());
            gen_threads.push(builder.spawn(move || {
                if online {
                    let constant_generator = stage1::ConstantFlowGenerator::new(*local_interfaces.first().unwrap(), *local_interfaces.last().unwrap());
                    stage1::run(constant_generator, rx_s1, tx_s1, online, local_interfaces);
                } else {
                    let flowchronicle_generator = flowchronicle::FCGenerator::new(patterns, online);
                    stage1::run(flowchronicle_generator, rx_s1, tx_s1, online, local_interfaces);
                }
            }).unwrap());
        }

        // STAGE 2

        let automata_library = Arc::new(tadam::AutomataLibrary::from_dir(Path::new(&args.models).join("tas").to_str().unwrap()));
        for _ in 0..STAGE2_COUNT {
            let rx_s2 = rx_s2.clone();
            let tx_s2 = tx_s2.clone();
            let generator = tadam::TadamGenerator::new(Arc::clone(&automata_library));
            let builder = thread::Builder::new().name("Stage2".into());
            gen_threads.push(builder.spawn(move || stage2::run(generator, rx_s2, tx_s2)).unwrap());
        }

        // STAGE 3

        for (proto, tx_s3_hm) in tx_s3.into_iter() {
            for _ in 0..STAGE3_COUNT {
                let tx_s3_hm = tx_s3_hm.clone();
                let tx_s3_to_collector = tx_s3_to_collector.clone();
                let stats = Arc::clone(&stats);

                let s3 = stage3::Stage3::new(args.taint);
                let builder = thread::Builder::new().name(format!("Stage3-{:?}", proto).into());

                match proto {
                    Protocol::TCP => {
                            let rx_s3_tcp = rx_s3_tcp.clone();
                            gen_threads.push(builder.spawn(move || stage3::run(|f| s3.generate_tcp_packets(f), rx_s3_tcp, tx_s3_hm, tx_s3_to_collector, stats, online)).unwrap());
                        },
                    Protocol::UDP => {
                            let rx_s3_udp = rx_s3_udp.clone();
                            gen_threads.push(builder.spawn(move || stage3::run(|f| s3.generate_udp_packets(f), rx_s3_udp, tx_s3_hm, tx_s3_to_collector, stats, online)).unwrap());
                    },
                    Protocol::ICMP => {
                            let rx_s3_icmp = rx_s3_icmp.clone();
                            gen_threads.push(builder.spawn(move || stage3::run(|f| s3.generate_icmp_packets(f), rx_s3_icmp, tx_s3_hm, tx_s3_to_collector, stats, online)).unwrap());
                    }
                }
            }
        }

        // PCAP EXPORT

        if let cmd::Command::Offline { outfile, .. } = &args.command {
            let builder = thread::Builder::new().name("Pcap-collector".into());
            gen_threads.push(builder.spawn(move || stage3::run_collector(rx_collector, tx_collector)).unwrap());

            let outfile = outfile.clone();
            let builder = thread::Builder::new().name("Pcap-export".into());
            gen_threads.push(builder.spawn(move || stage3::run_export(rx_pcap, &outfile)).unwrap());
        }

        // STAGE 4 (online mode only)

        if online {
            for ((iface, proto), rx) in rx_s4.into_iter() {
                for _ in 0..STAGE4_COUNT {
                    let rx = rx.clone();
                    let builder = thread::Builder::new().name(format!("Stage4-TCP-{}",iface));
                    gen_threads.push(builder.spawn(move || {
                        log::trace!("Start S4");
                        let s4 = stage4::Stage4::new(iface, proto.get_number());
                        while let Ok(packets) = rx.recv() {
                            s4.send(packets)
                        }
                        log::trace!("S4 stops");
                    }).unwrap());
                }
            }
        }

    }

    {
        let stats = Arc::clone(&stats);
        let running = Arc::clone(&running);
        let builder = thread::Builder::new().name("Monitoring".into());
        threads.push(builder.spawn(move || {
            loop {
                thread::sleep(Duration::new(1,0));
                {
                    let pc = stats.packets_counter.lock().unwrap();
                    let bc = stats.bytes_counter.lock().unwrap();
                    let throughput = 8. * (*bc as f64) / (Instant::now().duration_since(start_time).as_secs() as f64) / 1_000_000.;
                    if throughput < 1000. {
                        log::info!("{pc} created packets ({} Mbps)", throughput);
                    } else {
                        log::info!("{pc} created packets ({} Gbps)", throughput/1000.);
                    }
                    let running = running.lock().unwrap();
                    if !*running {
                        break;
                    }
                }
            }
        }).unwrap());
    }


    // Wait for the generation threads to end
    for thread in gen_threads.into_iter() {
        log::trace!("Waiting for thread {}", thread.thread().name().unwrap());
        thread.join().unwrap();
        log::trace!("Thread ended");
    }
    {
        // Tell the other threads to stop
        let mut running = running.lock().unwrap();
        *running = false;
    }
    // Wait for the other threads to stop
    for thread in threads.into_iter() {
        log::trace!("Waiting for thread {}", thread.thread().name().unwrap());
        thread.join().unwrap();
        log::trace!("Thread ended");
    }

}
