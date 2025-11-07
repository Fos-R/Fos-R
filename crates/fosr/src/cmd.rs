use clap::{Parser, Subcommand, ValueEnum};
use std::fmt;

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

#[derive(ValueEnum, Debug, Clone)]
pub enum GenerationProfile {
    Fast,
    Efficient,
}

impl fmt::Display for GenerationProfile {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", format!("{:?}", self).to_lowercase())
    }
}

#[derive(ValueEnum, Debug, Clone)]
pub enum InjectionAlgo {
    Fast,
    Reliable,
}

impl fmt::Display for InjectionAlgo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", format!("{:?}", self).to_lowercase())
    }
}

#[derive(Debug, Subcommand, Clone)]
pub enum Command {
    #[cfg(feature = "net_injection")]
    /// This mode requires the `iptables` or `ebpf` feature. In this mode, Fos-R generates and injects network traffic between different computers in the same network.
    /// Fos-R needs to be executed on each computer and provided a configuration file.
    Inject {
        #[arg(short, long, default_value = None, help = "Output pcap file of the generated packets")]
        outfile: Option<String>,
        #[arg(
            long,
            default_value_t = false,
            help = "Disable the temporal sorting of the generated pcap"
        )]
        no_order_pcap: bool,
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
            help = "Average number of flows to generate per day. Actual number of generated flows can be lower or higher"
        )]
        flow_per_day: Option<u64>,
        // #[arg(
        //     short,
        //     long,
        //     default_value = None,
        //     help = "Path to the profile with the models and the configuration"
        // )]
        // profile: Option<String>,
        #[arg(short = 'd', long, default_value = None, help = "Automatically stop the generation after this time. You can use human-friendly time, such as \"15days 30min 5s\"")]
        duration: Option<String>,
        #[arg(
            short,
            long,
            help = "Method to avoid kernel interactions with the injected traffic"
        )]
        net_enabler: NetEnabler,
        #[arg(
            short = 'a',
            long,
            default_value_t = InjectionAlgo::Reliable,
            help = "Algorithm for injecting on the wire"
        )]
        injection_algo: InjectionAlgo,
        #[arg(
            long,
            default_value_t = false,
            help = "Ensure the generated traffic is always the same. It makes Fos-R less robust to staggered process starts, so avoid it unless for testing"
        )]
        deterministic: bool,
    },
    /// Create a pcap file. If you require deterministic generation,
    /// you must specify -d, -t, --tz and --seed.
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
        #[arg(long, default_value_t = false, help = "Taint the packets")]
        taint: bool,
        #[arg(
            short,
            long,
            default_value_t = GenerationProfile::Efficient,
            help = "The generation profile to use. Either \"fast\" that optimizes CPU use but the entire dataset must fit in RAM, or \"efficient\" that requires less RAM but is slower"
        )]
        profile: GenerationProfile,
        // #[arg(
        //     short,
        //     long,
        //     default_value_t = false,
        //     help = "Add noise in the output file"
        // )]
        // noise: bool,
        #[arg(short = 'n', long, default_value = None, help = "Minimum number of packets to generate")]
        packets_count: Option<u64>,
        #[arg(short = 'd', long, default_value = None, help = "Minimum pcap traffic duration described in human-friendly time, such as \"15days 30min 5s\"")]
        duration: Option<String>,
        #[arg(short = 't', long, default_value = None, help = "Beginning time of the pcap in RFC3339 style (\"2025-05-01 10:28:07\") or a Unix timestamp. By default, use the current time. Date time is considered to be in the timezone specified with --tz")]
        start_time: Option<String>,
        #[arg(
            short,
            long,
            help = "Average number of flows to generate per day. Actual number of generated flows can be lower or higher"
        )]
        flow_per_day: Option<u64>,
        #[arg(
            short,
            long,
            help = "Number of generation jobs. By default, use half the available cores."
        )]
        jobs: Option<usize>,
        #[arg(short, long, help = "Seed for random number generation")]
        seed: Option<u64>,
        // #[arg(
        //     short,
        //     long,
        //     default_value = None,
        //     help = "Path to the profile with the models and the configuration"
        // )]
        // profile: Option<String>,
        #[arg(
            long,
            default_value = None,
            help = "Timezone of the generated, used for realistic work hours. By default, local timezone is used. Use a IANA time zone (like Europe/Paris) or an abbreviation (like CET). The offset is assumed constant during the generation time range"
        )]
        tz: Option<String>,
        #[arg(
            long,
            default_value_t = false,
            help = "Disable the temporal sorting of the generated pcap. Reduce significantly the RAM usage with \"--profile efficient\""
        )]
        no_order_pcap: bool,
    },
    /// Extract flow statistics from a pcap file to a csv file
    #[command(name = "pcap2flow")]
    Pcap2Flow {
        #[arg(short, long, required = true, help = "Pcap file to extract flows from")]
        input_pcap: String,
        #[arg(short, long, required = true, help = "CSV file to export flow into")]
        output_csv: String,
        #[arg(
            short = 'p',
            long,
            help = "Include the payloads in the CSV file",
            default_value_t = false
        )]
        include_payloads: bool,
    },
    /// Remove the Fos-R taint from a pcap file
    Untaint {
        #[arg(short, long, required = true, help = "Pcap file to untaint")]
        input: String,
        #[arg(short, long, required = true, help = "Pcap file output")]
        output: String,
    },
    // /// Replay a pcap file though the network interfaces. Errors (packet loss, non-responding
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
