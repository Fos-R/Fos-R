![](https://raw.githubusercontent.com/Fos-R/Fos-R/refs/heads/main/resources/logo.png)


[![pipeline status](https://gitlab.inria.fr/pirat-public/Fos-R/badges/main/pipeline.svg)](https://gitlab.inria.fr/pirat-public/Fos-R/-/commits/main) 
[![Latest Release](https://gitlab.inria.fr/pirat-public/Fos-R/-/badges/release.svg)](https://gitlab.inria.fr/pirat-public/Fos-R/-/releases)

Fos-R is a network traffic generator based on AI models. It does not require a GPU and can generate in the order of Gbps of network traffic with a laptop.

You can find the stable and experimental binaries on the [Fos-R website](https://fosr.inria.fr).

# Generation modes

## Create-pcap

In this mode, Fos-R outputs a pcap file generated with the AI models.

```
Usage: fosr create-pcap [OPTIONS] <--duration <DURATION>|--packets-count <PACKETS_COUNT>>

Options:
  -o, --outfile <OUTFILE>              Output pcap file for synthetic network packets [default: output.pcap]
      --taint                          Taint the packets
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

In this mode, Fos-R generates and play network traffic between different computers in the same network.
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
          Method to avoid kernel interactions with the injected traffic [possible values: ebpf]
  -a, --injection-algo <INJECTION_ALGO>
          Algorithm for injecting on the wire [default: reliable] [possible values: fast, reliable]
      --deterministic
          Ensure the generated traffic is always the same. It makes Fos-R less robust to staggered process starts, so avoid unless for testing
  -h, --help
          Print help
```

# Utilities

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

# Related scientific publications

- Schoen, A., Blanc, G., Gimenez, P. F., Han, Y., Majorczyk, F., & Mé, L. (2024). A Tale of Two Methods: Unveiling the limitations of GAN and the Rise of Bayesian Networks for Synthetic Network Traffic Generation. In Proceedings of the 9th International Workshop on Traffic Measurements for Cybersecurity (WTMC 2024).
- Cüppers, J., Schoen, A., Blanc, G. & Gimenez, P. F., (2024, December). FlowChronicle: Synthetic Network Flow Generation through Pattern Set Mining Generation. In the 20th International Conference on emerging Networking EXperiments and Technologies (CoNEXT).
- Cornanguer, L. & Gimenez, P. F., (2025 May). TADAM: Learning Timed Automata From Noisy Observations. In the SIAM International Conference on Data Mining (SDM25).
- Gimenez, P. F., (2025). Synthetic Network Traffic Generation for Intrusion Detection Systems: a Systematic Literature Review. In the ESORICS 2025 International Workshops.
