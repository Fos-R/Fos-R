#[cfg(feature = "net_injection")]
use fosr_lib::inject;
use fosr_lib::inject;
use fosr_lib::models;
use fosr_lib::network;
use fosr_lib::stage1;
use fosr_lib::stage2;
use fosr_lib::stage3;
use fosr_lib::stage4;
use fosr_lib::stats;
use fosr_lib::topo;
use fosr_lib::utils;

mod cmd;
mod run;
#[cfg(all(target_os = "linux", feature = "server"))]
mod server;

use std::cmp::max;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::DateTime;
use chrono::Offset;
use chrono::TimeZone;
use chrono_tz::Tz;
use clap::Parser;
#[cfg(feature = "net_injection")]
use pnet::{datalink, ipnetwork::IpNetwork};

// Use Jemalloc when possible
#[cfg(all(target_os = "linux", any(target_env = "", target_env = "gnu")))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// The entry point of the application.
///
/// This function prepare the parameter for the function "run" according to the command line
fn main() -> Result<(), String> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = cmd::Args::parse();

    match args.command {
        #[cfg(feature = "net_injection")]
        cmd::Command::InjectCyberRange {
            #[cfg(all(target_os = "linux", feature = "iptables"))]
            stealthy,
            seed,
            network,
            outfile,
            no_order_pcap,
            flow_per_day,
            net_enabler,
            duration,
            jobs,
            deterministic,
            injection_algo,
            default_models,
            custom_models,
        } => {
            // load the models
            let source = if let Some(custom_models) = custom_models {
                models::ModelsSource::UserDefined(custom_models)
            } else {
                default_models?.get_source() // we are sure it contains something
            };
            let duration = duration
                .map(|d| humantime::parse_duration(&d).expect("Duration could not be parsed."));
            #[cfg(not(all(target_os = "linux", feature = "iptables")))]
            let stealthy = false;
            net_injection(
                stealthy,
                seed,
                network,
                outfile,
                no_order_pcap,
                flow_per_day,
                net_enabler,
                duration,
                jobs,
                deterministic,
                injection_algo,
                source,
            );
        }
        #[cfg(all(any(target_os = "windows", target_os = "linux"), feature = "ebpf"))]
        cmd::Command::InjectAcross {
            seed,
            network,
            outfile,
            no_order_pcap,
            flow_per_day,
            duration,
            jobs,
            default_models,
            custom_models,
        } => {
            // load the models
            let source = if let Some(custom_models) = custom_models {
                models::ModelsSource::UserDefined(custom_models)
            } else {
                default_models?.get_source() // we are sure it contains something
            };
            let duration = duration
                .map(|d| humantime::parse_duration(&d).expect("Duration could not be parsed."));
            net_injection(
                false,
                seed,
                network,
                outfile,
                no_order_pcap,
                flow_per_day,
                cmd::NetEnabler::Ebpf,
                duration,
                jobs,
                true,
                cmd::InjectionAlgo::Fast,
                source,
            );
        }
        cmd::Command::CreatePcap {
            seed,
            outfile,
            profile,
            no_order_pcap,
            start_time,
            duration,
            flow_per_day,
            tz,
            jobs,
            alpha,
            network,
            taint,
            default_models,
            custom_models,
        } => {
            // load the models
            let source = if let Some(custom_models) = custom_models {
                models::ModelsSource::UserDefined(custom_models)
            } else {
                default_models.unwrap().get_source() // we are sure it contains something
            };

            let model = models::Models::from_source_with_path_network(&source, &network, alpha)?;

            generate_pcap(
                duration,
                seed,
                run::ExportParams {
                    outfile: run::ExportDestination::FileName(outfile),
                    order_pcap: !no_order_pcap,
                },
                profile,
                start_time,
                flow_per_day,
                tz,
                jobs,
                taint,
                model.into(),
            )?;
        }
        cmd::Command::AugmentDataset {
            seed,
            alpha,
            outfile,
            profile,
            no_order_pcap,
            start_time,
            duration,
            tz,
            jobs,
            taint,
            default_models,
            custom_models,
        } => {
            // load the models
            let source = if let Some(custom_models) = custom_models {
                models::ModelsSource::UserDefined(custom_models)
            } else {
                default_models.unwrap().get_source() // we are sure it contains something
            };

            let model = models::Models::from_source(&source, alpha)?;

            generate_pcap(
                duration,
                seed,
                run::ExportParams {
                    outfile: run::ExportDestination::FileName(outfile),
                    order_pcap: !no_order_pcap,
                },
                profile,
                start_time,
                None,
                tz,
                jobs,
                taint,
                model.into(),
            )?;
        }
        #[cfg(all(target_os = "linux", feature = "server"))]
        cmd::Command::WebServer {
            port,
            maximum_duration,
            default_models,
            jobs,
        } => {
            // load the models
            let source = default_models
                .unwrap_or(cmd::CreateDefaultModels::CCD)
                .get_source();

            let model = models::Models::from_source_for_transfer_learning(&source, 1)?;

            server::start(
                port,
                maximum_duration.map(|d| Duration::from_secs_f64((d as f64) / 3600.0)),
                model,
                jobs,
            )?;
        }

        cmd::Command::Untaint { input, output } => {
            utils::untaint_file(&input, &output);
        }

        cmd::Command::SplitUntaint { input } => {
            utils::split_untaint(&input);
        }

        cmd::Command::GenerateTopology {
            outfile,
            min_subnets,
            min_nodes,
            time_limit,
            // tree_depth,
            no_internet_access,
            with_web_server,
            with_ftp_server,
            with_mail_server,
            with_cloud_storage,
            with_log_server,
            with_dbms_server,
            with_cms_server,
            with_proxy_server,
            with_ldap_server,
            with_dns_server,
            with_ssh_server,
        } => {
            let mut services: Vec<topo::config::Service> = vec![];
            if with_web_server {
                services.push(topo::config::Service::WebServer);
            }
            if with_ftp_server {
                services.push(topo::config::Service::FtpServer);
            }
            if with_mail_server {
                services.push(topo::config::Service::MailServer);
            }
            if with_cloud_storage {
                services.push(topo::config::Service::CloudStorage);
            }
            if with_log_server {
                services.push(topo::config::Service::LogServer);
            }
            if with_dbms_server {
                services.push(topo::config::Service::DbmsServer);
            }
            if with_cms_server {
                services.push(topo::config::Service::CmsServer);
            }
            if with_proxy_server {
                services.push(topo::config::Service::ProxyServer);
            }
            if with_ldap_server {
                services.push(topo::config::Service::LdapServer);
            }
            if with_dns_server {
                services.push(topo::config::Service::DnsServer);
            }
            if with_ssh_server {
                services.push(topo::config::Service::SshServer);
            }

            let gen_params = topo::config::GenerationParameters {
                minimum_sub_topology: min_subnets,
                minimum_node_count: min_nodes,
                no_internet_access,
                // tree_depth,
                services,
                time_limit: time_limit.map(Duration::from_secs),
            };
            log::info!("Starting the topology generation");
            if time_limit.is_none() {
                log::info!(
                    "Depending on the contraints, it can take up to 10 minutes. Consider adding a time limit."
                );
            }
            let topology = network::NetworkYaml::from(topo::generator::generate_topology(
                &topo::subtopo::get_default_subtopos(),
                &gen_params,
            )?);
            let mut file =
                File::create(&outfile).expect("Failed to create or open the topology file");
            file.write_all(
                serde_yaml::to_string(&topology)
                    .expect("Serialization issue")
                    .as_bytes(),
            )
            .expect("Failed to write to the file");
            log::info!("Topology has been successfully generated into {outfile}");
        }
        cmd::Command::ValidateNetwork { input } => {
            network::import_network(
                &fs::read_to_string(Path::new(&input))
                    .map_err(|e| format!("Cannot open the network file: {e}"))?,
            );
            log::info!("Network is valid.");
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn generate_pcap(
    duration: String,
    seed: Option<u64>,
    export: run::ExportParams,
    profile: cmd::GenerationProfile,
    start_time: Option<String>,
    flow_per_day: Option<u64>,
    tz: Option<String>,
    jobs: Option<usize>,
    taint: bool,
    model: models::ArcModels,
) -> Result<(), String> {
    // let automata_library = Arc::new(model.automata);
    // let bn = Arc::new(model.bn);
    let duration = humantime::parse_duration(&duration).expect("Duration could not be parsed.");
    let target = stats::Target::GenerationDuration(duration);

    if let Some(s) = seed {
        log::info!("Generating with seed {s}");
    }

    let (mut initial_ts, ts_requires_offset): (Duration, bool) =
        if let Some(start_time) = start_time {
            // try to parse a date
            if let Ok(d) = humantime::parse_rfc3339_weak(&start_time) {
                (
                    d.duration_since(UNIX_EPOCH).map_err(|e| e.to_string())?,
                    true,
                )
            } else if let Ok(n) = start_time.parse::<u64>() {
                (Duration::from_secs(n), false)
            } else {
                panic!("Could not parse start time");
            }
        } else {
            (
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|e| e.to_string())?,
                false,
            )
        };

    let tz_offset = if let Some(tz_str) = tz {
        let tz: Tz = tz_str.parse().expect("Could not parse the timezone");
        let date = DateTime::from_timestamp(initial_ts.as_secs() as i64, 0)
            .unwrap()
            .naive_utc();
        let tz = tz.offset_from_utc_datetime(&date).fix();
        log::info!("Using {tz_str} timezone (UTC{tz})");
        tz
    } else {
        let date = DateTime::from_timestamp(initial_ts.as_secs() as i64, 0)
            .unwrap()
            .naive_utc();
        let tz = chrono::Local::now()
            .timezone()
            .offset_from_local_datetime(&date)
            .single()
            .expect("Ambiguous local date from timestamp")
            .fix();
        log::info!("Using local timezone (UTC{tz})");
        tz
    };

    // the initial timestamp was computed assuming that the timezone is UTC.
    // now, compute the actual timestamp taking into account the timezone
    if ts_requires_offset {
        let duration: i64 = DateTime::from_timestamp(initial_ts.as_secs() as i64, 0)
            .unwrap()
            .naive_utc()
            .and_local_timezone(tz_offset)
            .unwrap()
            .timestamp();
        let duration: u64 = i64::try_into(duration).expect("Time before UNIX epoch!");
        initial_ts = Duration::from_secs(duration);
    }

    let s1 = stage1::BinBasedGenerator::new(
        seed,
        false,
        flow_per_day,
        model.time_bins,
        initial_ts,
        Some(duration),
        tz_offset,
    );
    let s2 = stage2::bn_generator::BNGenerator::new(model.bn, false);
    let s3 = stage3::tadam::TadamGenerator::new(model.automata);
    let s4 = stage4::Stage4::new(taint); //, model.network);
    let jobs = jobs.unwrap_or(max(1, num_cpus::get() / 2));

    match profile {
        cmd::GenerationProfile::Fast => {
            run::run_fast(
                export,
                s1,
                s2,
                s3,
                s4,
                jobs,
                Arc::new(stats::Stats::new(target)),
            )?;
        }
        cmd::GenerationProfile::Auto if duration <= Duration::from_secs(24 * 60 * 60) => {
            run::run_fast(
                export,
                s1,
                s2,
                s3,
                s4,
                jobs,
                Arc::new(stats::Stats::new(target)),
            )?;
        }
        cmd::GenerationProfile::Efficient | cmd::GenerationProfile::Auto => {
            let (s2_count, s3_count, s4_count) = (
                max(1, jobs / 3),
                max(1, jobs / 3),
                max(1, jobs - 2 * (jobs / 3)),
            );
            run::run_efficient(
                vec![],
                Some(export),
                s1,
                (s2, s2_count),
                (s3, s3_count),
                (s4, s4_count),
                Arc::new(stats::Stats::new(target)),
                None::<run::InjectParam<inject::DummyNetEnabler>>,
            )?;
        }
    }
    Ok(())
}

#[cfg(feature = "net_injection")]
fn net_injection(
    stealthy: bool,
    seed: Option<u64>,
    network: String,
    outfile: Option<String>,
    no_order_pcap: bool,
    flow_per_day: Option<u64>,
    net_enabler: cmd::NetEnabler,
    duration: Option<Duration>,
    jobs: Option<usize>,
    deterministic: bool,
    injection_algo: cmd::InjectionAlgo,
    source: models::ModelsSource,
) -> Result<(), String> {
    // Extract all IPv4 local interfaces (except loopback)
    let extract_addr = |iface: datalink::NetworkInterface| {
        iface
            .ips
            .into_iter()
            .filter(IpNetwork::is_ipv4)
            .map(|i| match i {
                IpNetwork::V4(data) => data.ip(),
                _ => unreachable!(),
            })
    };
    // the local interfaces are used by the stage 4 and to identify local IPs
    // we do not include loopback interfaces or interfaces without an IPv4 address
    let local_interfaces: Vec<datalink::NetworkInterface> = datalink::interfaces()
        .into_iter()
        .filter(|iface| !iface.is_loopback() && iface.ips.iter().any(IpNetwork::is_ipv4))
        .collect();
    // for each interface, we extract its addresses
    let local_ips: Vec<Ipv4Addr> = local_interfaces
        .clone()
        .into_iter()
        .flat_map(extract_addr)
        .filter(|i| !i.is_loopback())
        .collect();
    log::debug!("IPv4 interfaces: {:?}", &local_ips);

    let model = models::Models::from_source(source)?; //.with_network(&network).unwrap(); // FIXME
    let automata_library = Arc::new(model.automata);
    let bn = Arc::new(model.bn);

    // TODO verify if the current IP has a role in the network
    // if !has_role {
    //     log::error!("This computer has no traffic to inject with this network file! Exiting.");
    //     process::exit(1);
    // }

    // load the models
    let s1 = stage1::BinBasedGenerator::new_for_injection(
        seed,
        duration,
        flow_per_day,
        model.time_bins,
        deterministic,
    );

    let s2 = stage2::bn_generator::BNGenerator::new(bn, false);
    let s2 = stage2::FilterForOnline::new(local_ips.clone(), s2);
    let s3 = stage3::tadam::TadamGenerator::new(automata_library);
    let s4 = stage4::Stage4::new(!stealthy);

    // run
    let jobs = jobs.unwrap_or(max(1, num_cpus::get() / 2));
    let (s2_count, s3_count, s4_count) = (
        max(1, jobs / 3),
        max(1, jobs / 3),
        max(1, jobs - (2 * jobs) / 3),
    );

    log::info!("Network enabler: {net_enabler:?}");
    match net_enabler {
        #[cfg(all(any(target_os = "windows", target_os = "linux"), feature = "ebpf"))]
        cmd::NetEnabler::Ebpf => {
            let s4net = run::InjectParam {
                net_enabler: inject::ebpf::EBPFNetEnabler::new(
                    matches!(injection_algo, cmd::InjectionAlgo::Fast),
                    &local_interfaces,
                ),
                injection_algo,
            };
            run_efficient(
                local_ips,
                outfile.map(|o| ExportParams {
                    outfile: ExportDestination::FileName(o),
                    order_pcap: !no_order_pcap,
                }),
                s1,
                (s2, s2_count),
                (s3, s3_count),
                (s4, s4_count),
                Arc::new(stats::Stats::new(stats::Target::None)),
                Some(s4net),
            );
        }
        #[cfg(all(target_os = "linux", feature = "iptables"))]
        cmd::NetEnabler::Iptables => {
            let s4net = run::InjectParam {
                net_enabler: inject::iptables::IPTablesNetEnabler::new(!stealthy, false),
                injection_algo,
            };
            run_efficient(
                local_ips,
                outfile.map(|o| ExportParams {
                    outfile: ExportDestination::FileName(o),
                    order_pcap: !no_order_pcap,
                }),
                s1,
                (s2, s2_count),
                (s3, s3_count),
                (s4, s4_count),
                Arc::new(stats::Stats::new(stats::Target::None)),
                Some(s4net),
            );
        }
    };
    Ok(())
}
