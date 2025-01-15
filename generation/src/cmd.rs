use clap::{Parser, Subcommand};

#[derive(Debug, Parser, Clone)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    #[clap(subcommand)]
    pub command: Command,

    #[arg(short, long, global=true, default_value_t=false, help="Taint the packets to easily identify them")]
    pub taint: bool,
    #[arg(short, long, global=true, help="Seed for random number generation")]
    pub seed: Option<u64>,
    #[arg(short, long, global=true, default_value="../models/test", help="Path to models directory")] // TODO utiliser include_str
    pub models: String,

}

#[derive(Debug, Subcommand, Clone)]
pub enum Command {
    /// Online mode: send packets through the network interfaces
    Online {
        // TODO: API pour synchroniser les agents online
    },
    /// Offline mode: generate a pcap file
    Offline {
        #[arg(short, long, default_value="output.pcap", help="Output pcap file for synthetic network packets")] // TODO: remove default for release
        outfile: String,
        #[arg(short, long, default_value_t=false, help="Add noise in the output file")]
        noise: bool,
        #[arg(short, long, default_value_t=1, help="Minimum number of flows to generate.")] // TODO: use default value "1" for release
        flow_count: i32,
        #[arg(short='d', long, default_value=None, help="Unix time for the beginning of the pcap. By default, use current time.")]
        start_unix_time: Option<u64>
    }
}


