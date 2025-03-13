use clap::{Parser, Subcommand};

#[derive(Debug, Parser, Clone)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand, Clone)]
pub enum Command {
    // /// Replay a pcap file though the network interfaces. Errors (packet loss, non-responding
    // /// hosts, etc.) are ignored.
    // Replay {
    //     #[arg(short, long, help = "Input pcap file to replay")]
    //     infile: String,
    //     #[arg(short='d', long, default_value=None, help="Time to start the replay of the pcap file. Default: starts now.")]
    //     start_time: Option<String>,
    //     #[arg(
    //         short,
    //         long,
    //         default_value_t = false,
    //         help = "Taint the packets to easily identify them"
    //     )]
    //     taint: bool,
    // },
    /// Generate and play network activity between hosts. Computers defined in the config file can
    /// easily join or exit the activity.
    Honeynet {
        #[arg(short, long, default_value=None, help="Output pcap file of generated packets")]
        outfile: Option<String>,
        #[arg(
            short,
            long,
            default_value_t = false,
            help = "Taint the packets to easily identify them"
        )]
        taint: bool,
        #[arg(short, long, default_value=None, help="Path to the patterns file")]
        patterns: Option<String>,
        #[arg(short, long, default_value=None, help="Path to automata directory")]
        automata: Option<String>,
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
            default_value=None,
            help = "Path to the information system configuration file"
        )]
        config_path: Option<String>,
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
        // #[arg(
        //     short,
        //     long,
        //     default_value_t = false,
        //     help = "Add noise in the output file"
        // )]
        // noise: bool,
        #[arg(
            short,
            long,
            default_value_t = 10,
            help = "Minimum number of flows to generate."
        )] // TODO: remove default value for release
        flow_count: u64,
        #[arg(short='d', long, default_value=None, help="Unix time for the beginning of the pcap. By default, use current time.")]
        start_unix_time: Option<u64>,
        #[arg(short, long, help = "Seed for random number generation")]
        seed: Option<u64>,
        #[arg(short, long, default_value=None, help="Path to the patterns file")]
        patterns: Option<String>,
        #[arg(short, long, default_value=None, help="Path to automata directory")]
        automata: Option<String>,
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
            default_value=None,
            help = "Path to the information system configuration file"
        )]
        config_path: Option<String>,
    },
    Replay {
        #[arg(
            short,
            long,
            default_value="output.pcap",
            help = "Path to the pcap file to be replayed"
        )]
        file: String,
    },
}
