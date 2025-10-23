# How to use Fos-R

Fos-R contains several subcommands.

## Pcap creation

In this mode, Fos-R outputs a pcap file generated with the AI models.

```
Usage: fosr create-pcap [OPTIONS] <--duration <DURATION>|--packets-count <PACKETS_COUNT>>

Options:
  -o, --outfile <OUTFILE>              Output pcap file for synthetic network packets [default: output.pcap]
      --minimum-threads                Use as few threads as possible
  -n, --packets-count <PACKETS_COUNT>  Minimum number of packets to generate. Beware: generation is not deterministic.
  -d, --duration <DURATION>            Minimum pcap traffic duration described in human-friendly time, such as "15days 30min 5s". Generation is deterministic when used with --order-pcap and --seed.
  -t, --start-time <START_TIME>        Beginning time of the pcap in RFC3339 style ("2025-05-01 10:28:07") or a Unix timestamp. By default, use current time
      --order-pcap                     Reorder temporally the generated pcap. Must fit the entire dataset in RAM !
  -s, --seed <SEED>                    Seed for random number generation
  -p, --profile <PROFILE>              Path to the profile with the models and the configuration
  -h, --help                           Print help
```

If you need a deterministic generation, make sure to specify a seed with `-s`, to set a maximum duration with `-d`, to use `--order-pcap` and to set a start time with `-t`.

## Network injection

This mode requires the `iptables` or `ebpf` feature. In this mode, Fos-R generates and injects network traffic between different computers in the same network.
Fos-R needs to be executed on each computer and provided a configuration file.

```
Usage: fosr inject [OPTIONS] --net-enabler <NET_ENABLER>

Options:
  -o, --outfile <OUTFILE>
          Output pcap file of generated packets
      --order-pcap
          Reorder temporally the generated pcap. Must fit the entire dataset in RAM ! Requires --outfile.
  -s, --seed <SEED>
          Seed for random number generation. All participants must use the same seed!
  -f, --flow-per-second <FLOW_PER_SECOND>
          Overall number of flows to generate per second [default: 10]
  -p, --profile <PROFILE>
          Path to the profile with the models and the configuration
  -d, --duration <DURATION>
          Minimum pcap traffic duration described in human-friendly time, such as "15days 30min 5s"
  -n, --net-enabler <NET_ENABLER>
          Method to avoid kernel interactions with the injected traffic [possible values: iptables, ebpf]
  -a, --injection-algo <INJECTION_ALGO>
          Algorithm for injecting on the wire [default: reliable] [possible values: fast, reliable]
      --deterministic
          Ensure the generated traffic is always the same. It makes Fos-R less robust to staggered process starts, so avoid unless for testing
  -h, --help
          Print help
```

## pcap2flow

Extract flow statistics from a pcap file to a csv file

```
Usage: fosr pcap2flow [OPTIONS] --input-pcap <INPUT_PCAP> --output-csv <OUTPUT_CSV>

Options:
  -i, --input-pcap <INPUT_PCAP>  Pcap file to extract flows from
  -o, --output-csv <OUTPUT_CSV>  Csv file to export flow into
  -p, --include-payloads         Include the payloads into the csv file
  -h, --help                     Print help
```

## Untaint pcap file

Remove the Fos-R taint from a pcap file

```
Usage: fosr untaint --input <INPUT> --output <OUTPUT>

Options:
  -i, --input <INPUT>    Pcap file to untaint
  -o, --output <OUTPUT>  Pcap file output
  -h, --help             Print help
```
