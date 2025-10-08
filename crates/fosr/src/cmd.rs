use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser, Clone)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    #[clap(subcommand)]
    pub command: Command,
}

#[derive(ValueEnum, Debug, Clone)]
pub enum NetEnabler {
    #[cfg(all(target_os = "linux", feature = "iptables"))]
    Iptables,
    #[cfg(all(any(target_os = "windows", target_os = "linux"), feature = "ebpf"))]
    Ebpf,
}

#[derive(Debug, Subcommand, Clone)]
pub enum Command {
    #[cfg(feature = "net_injection")]
    /// Generate network activity and inject it on the wire
    Inject {
        #[arg(short, long, default_value = None, help = "Output pcap file of generated packets")]
        outfile: Option<String>,
        #[arg(
            long,
            default_value_t = false,
            help = "Reorder temporally the generated pcap. Must fit the entire dataset in RAM ! Requires --outfile."
        )]
        order_pcap: bool,
        #[cfg(all(target_os = "linux", feature = "iptables"))]
        #[arg(
            long,
            default_value_t = false,
            help = "Do not taint the packets. Option only available on Linux with the \"iptables\" feature."
        )]
        stealthy: bool,
        #[arg(
            short,
            long,
            help = "Seed for random number generation. All participants must use the same seed!"
        )]
        seed: Option<u64>,
        #[arg(
            short,
            long,
            default_value_t = 10,
            help = "Overall number of flows to generate per second"
        )]
        flow_per_second: u64,
        #[arg(
            short,
            long,
            default_value = None,
            help = "Path to the profile with the models and the configuration"
        )]
        profile: Option<String>,
        #[arg(short = 'd', long, default_value = None, help = "Minimum pcap traffic duration described in human-friendly time, such as \"15days 30min 5s\"")]
        duration: Option<String>,
        #[arg(
            short,
            long,
            help = "Method to avoid kernel interactions with the injected traffic"
        )]
        net_enabler: NetEnabler,
        #[arg(
            long,
            default_value_t = false,
            help = "Ensure the generated traffic is always the same. It makes Fos-R less robust to staggered process starts, so avoid unless for testing"
        )]
        deterministic: bool,
    },
    /// Extend a pcap file. You should use your own models that have been
    /// fitted on that pcap file.
    #[clap(group(
    clap::ArgGroup::new("target")
        .required(true)
        .args(&["duration", "packets_count"]),
    ))]
    CreatePcap {
        #[arg(
            short,
            long,
            default_value = "output.pcap",
            help = "Output pcap file for synthetic network packets"
        )]
        outfile: String,
        #[arg(long, default_value_t = false, help = "Use as few threads as possible")]
        minimum_threads: bool,
        // #[arg(
        //     short,
        //     long,
        //     default_value_t = false,
        //     help = "Add noise in the output file"
        // )]
        // noise: bool,
        #[arg(short = 'n', long, default_value = None, help = "Minimum number of packets to generate. Beware: generation is not deterministic.")]
        packets_count: Option<u64>,
        #[arg(short = 'd', long, default_value = None, help = "Minimum pcap traffic duration described in human-friendly time, such as \"15days 30min 5s\". Generation is deterministic when used with --order-pcap and --seed.")]
        duration: Option<String>,
        #[arg(short = 't', long, default_value = None, help = "Beginning time of the pcap in RFC3339 style (\"2025-05-01 10:28:07\") or a Unix timestamp. By default, use current time")]
        start_time: Option<String>,
        #[arg(
            long,
            default_value_t = false,
            help = "Reorder temporally the generated pcap. Must fit the entire dataset in RAM !"
        )]
        order_pcap: bool,
        #[arg(short, long, help = "Seed for random number generation")]
        seed: Option<u64>,
        #[arg(
            short,
            long,
            default_value = None,
            help = "Path to the profile with the models and the configuration"
        )]
        profile: Option<String>,
    },
    /// Extract flow statistics from a pcap file to a csv file
    #[command(name = "pcap2flow")]
    Pcap2Flow {
        #[arg(short, long, required = true, help = "Pcap file to extract flows from")]
        input_pcap: String,
        #[arg(short, long, required = true, help = "Csv file to export flow into")]
        output_csv: String,
        #[arg(
            short = 'p',
            long,
            help = "Include the payloads into the csv file",
            default_value_t = false
        )]
        include_payloads: bool,
    }, // /// Replay a pcap file though the network interfaces. Errors (packet loss, non-responding
       // /// hosts, etc.) are ignored.
       // #[cfg(feature = "replay")]
       // Replay {
       //     #[arg(short, long, help = "Path to the pcap file to be replayed")]
       //     file: String,
       //     // #[arg(
       //     //     short,
       //     //     long,
       //     //     default_value = None,
       //     //     help = "Path to the information system configuration file"
       //     // )]
       //     // config_path: Option<String>,
       //     #[arg(
       //         short,
       //         long,
       //         default_value_t = false,
       //         help = "Taint the packets to easily identify them"
       //     )]
       //     taint: bool,
       //     #[arg(
       //         long,
       //         default_value_t = false,
       //         help = "Ignores timestamps and send packets without waiting"
       //     )]
       //     fast: bool,
       // },
}
