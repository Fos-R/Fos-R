use fosr_lib::models;

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

#[derive(ValueEnum, Debug, Clone)]
#[allow(clippy::upper_case_acronyms)]
pub enum DefaultModels {
    CICIDS17,
    CUPID,
}

impl DefaultModels {
    pub fn get_source(&self) -> models::ModelsSource {
        match &self {
            DefaultModels::CICIDS17 => models::ModelsSource::CICIDS17,
            DefaultModels::CUPID => models::ModelsSource::CUPID,
        }
    }
}

impl fmt::Display for DefaultModels {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", format!("{:?}", self).to_lowercase())
    }
}

#[derive(Debug, Subcommand, Clone)]
pub enum Command {
    #[cfg(feature = "net_injection")]
    /// This mode generates and injects network traffic between different computers in the same network.
    /// Fos-R needs to be executed on each computer.
    #[clap(group(
    clap::ArgGroup::new("models")
        .required(true)
        .args(&["default_models", "custom_models"]),

    ))]
    InjectWithin {
        #[arg(short, long, help = "Output pcap file of the generated packets")]
        outfile: Option<String>,
        #[arg(
            long,
            requires = "outfile",
            default_value_t = false,
            help = "Disable the temporal sorting of the generated pcap"
        )]
        no_order_pcap: bool,
        #[arg(short = 'm', long, help = "Use a default model")]
        default_models: Option<DefaultModels>,
        #[arg(long, help = "Use a custom model")]
        custom_models: Option<String>,
        #[arg(short, long, help = "Path to the network file")]
        network: String,
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
        #[arg(
            short = 'd',
            long,
            help = "Automatically stop the generation after this time. You can use human-friendly time, such as \"15days 30min 5s\""
        )]
        duration: Option<String>,
        #[arg(
            short = 'e',
            long,
            help = "Method to avoid kernel interactions with the injected traffic"
        )]
        net_enabler: NetEnabler,
        #[arg(
            short,
            long,
            help = "Number of generation jobs. By default, use half the available cores"
        )]
        jobs: Option<usize>,
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

    #[cfg(all(any(target_os = "windows", target_os = "linux"), feature = "ebpf"))]
    /// This mode injects traffic from two network interfaces, across some network equipment to analyse.
    #[clap(group(
    clap::ArgGroup::new("models")
        .required(true)
        .args(&["default_models", "custom_models"]),

    ))]
    InjectAcross {
        // TODO: ajouter les deux interfaces
        #[arg(short, long, help = "Output pcap file of the generated packets")]
        outfile: Option<String>,
        #[arg(
            long,
            requires = "outfile",
            default_value_t = false,
            help = "Disable the temporal sorting of the generated pcap"
        )]
        no_order_pcap: bool,
        #[arg(short = 'm', long, help = "Use a default model")]
        default_models: Option<DefaultModels>,
        #[arg(long, help = "Use a custom model")]
        custom_models: Option<String>,
        #[arg(short, long, help = "Path to the network file")]
        network: String,
        #[arg(
            short,
            long,
            help = "Seed for random number generation"
        )]
        seed: Option<u64>,
        #[arg(
            short,
            long,
            help = "Average number of flows to generate per day. Actual number of generated flows can be lower or higher"
        )]
        flow_per_day: Option<u64>,
        #[arg(
            short = 'd',
            long,
            help = "Automatically stop the generation after this time. You can use human-friendly time, such as \"15days 30min 5s\""
        )]
        duration: Option<String>,
        #[arg(
            short,
            long,
            help = "Number of generation jobs. By default, use half the available cores"
        )]
        jobs: Option<usize>,
    },

    /// Create a pcap file. If you require deterministic generation,
    /// you must specify -d, -t, --tz and --seed.
    #[clap(group(
    clap::ArgGroup::new("target")
        .required(true)
        .args(&["duration", "packets_count"])),
    group(
    clap::ArgGroup::new("models")
        .required(true)
        .args(&["default_models", "custom_models"]),

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
        #[arg(short, long, help = "Path to the network file")]
        network: Option<String>,
        #[arg(long, help = "Minimum number of packets to generate")]
        packets_count: Option<u64>,
        #[arg(
            short = 'd',
            long,
            help = "Minimum pcap traffic duration described in human-friendly time, such as \"15days 30min 5s\""
        )]
        duration: Option<String>,
        #[arg(
            short = 't',
            long,
            help = "Beginning time of the pcap in RFC3339 style (\"2025-05-01 10:28:07\") or a Unix timestamp. By default, use the current time. Date time is considered to be in the timezone specified with --tz"
        )]
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
            help = "Number of generation jobs. By default, use half the available cores"
        )]
        jobs: Option<usize>,
        #[arg(short, long, help = "Seed for random number generation")]
        seed: Option<u64>,
        #[arg(short = 'm', long, help = "Use a default model")]
        default_models: Option<DefaultModels>,
        #[arg(long, help = "Use a custom model")]
        custom_models: Option<String>,
        #[arg(
            long,
            help = "Timezone of the generated, used for realistic work hours. By default, local timezone is used. Use a IANA time zone (like Europe/Paris) or an abbreviation (like CET). The offset is assumed constant during the generation time range"
        )]
        tz: Option<String>,
        #[arg(
            long,
            default_value_t = false,
            help = "Disable the temporal sorting of the generated pcap. Reduce significantly the RAM usage when used with \"--profile efficient\""
        )]
        no_order_pcap: bool,
    },
    /// Remove the Fos-R taint from a pcap file
    Untaint {
        #[arg(short, long, required = true, help = "Pcap file to untaint")]
        input: String,
        #[arg(short, long, required = true, help = "Pcap file output")]
        output: String,
    },
}
