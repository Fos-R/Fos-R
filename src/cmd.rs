use clap::{Parser, Subcommand};

#[derive(Debug, Parser, Clone)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand, Clone)]
pub enum Command {
    /// Generate and play network activity between hosts. Computers defined in the config file can
    /// easily join or exit the activity.
    #[cfg(feature = "net_injection")]
    Inject {
        #[arg(short, long, default_value = None, help = "Output pcap file of generated packets")]
        outfile: Option<String>,
        #[arg(
            short,
            long,
            default_value_t = false,
            help = "Taint the packets to easily identify them"
        )]
        taint: bool,
        #[arg(short, long, help = "Seed for random number generation")]
        seed: Option<u64>,
        #[arg(
            short = 'u',
            long,
            default_value_t = false,
            help = "Show CPU usage per thread"
        )]
        cpu_usage: bool,
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
            help = "Path to the profil with the models and the configuration"
        )]
        profil: Option<String>,
    },
    /// Perform data augmentation on a pcap file. You should use your own models that have been
    /// fitted on that pcap file.
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
        #[arg(short = 'n', long, default_value = None, help = "Minimum number of packets to generate. Generation is not deterministic.")]
        packets_count: Option<u64>,
        #[arg(short = 'd', long, default_value = None, help = "Minimum pcap traffic duration described in human-friendly time, such as \"15days 30min 5s\". Generation is deterministic.")]
        duration: Option<String>, // TODO: packet_count et duration sont mutuellement exclusif mais
        // l’un des deux doit être fourni
        #[arg(short = 't', long, default_value = None, help = "Beginning time of the pcap in RFC3339 style (\"2025-05-01 10:28:07\") or a Unix timestamp. By default, use current time")]
        start_time: Option<String>,
        #[arg(
            long,
            default_value_t = false,
            help = "Reorder temporally the generated pcap. Must fit the entire dataset in RAM."
        )]
        order_pcap: bool,
        #[arg(short, long, help = "Seed for random number generation")]
        seed: Option<u64>,
        #[arg(
            short = 'u',
            long,
            default_value_t = false,
            help = "Show CPU usage per thread"
        )]
        cpu_usage: bool,
        #[arg(
            short,
            long,
            default_value = None,
            help = "Path to the profil with the models and the configuration"
        )]
        profil: Option<String>,
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
