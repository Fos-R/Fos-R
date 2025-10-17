![](https://raw.githubusercontent.com/Fos-R/Fos-R/refs/heads/main/resources/logo.png)


[![pipeline status](https://gitlab.inria.fr/pirat-public/Fos-R/badges/main/pipeline.svg)](https://gitlab.inria.fr/pirat-public/Fos-R/-/commits/main) 
[![Latest Release](https://gitlab.inria.fr/pirat-public/Fos-R/-/badges/release.svg)](https://gitlab.inria.fr/pirat-public/Fos-R/-/releases)

Fos-R is a network traffic generator based on AI models. It does not require GPU and can generate in the order of Gbps of network traffic with a laptop.

## Binaries

You can either download the last stable version from the [release page](https://gitlab.inria.fr/pirat-public/Fos-R/-/releases) or download the most recent binaries from the [CI/CD pipeline](https://pirat-public.gitlabpages.inria.fr/Fos-R/).

## Compiling from sources

Install Rust, preferably with [rustup.rs](https://rustup.rs/).

### Version with eBPF

You need to install the nightly toolchain and `bpf-linker` to enable eBPF support:
```
$ rustup toolchain install nightly --component rust-src
$ cargo install bpf-linker
```

Then, you can install Fos-R with:

    $ cargo install fosr

Then, you can check the install with:

    $ fosr

If you want Fos-R to use the network, you must execute it as root/administrator.

### Version without eBPF

If you cannot or prefer not to use eBPF, you can download the version without network injection:

    $ cargo install --no-default-features fosr

Then, you can check the install with:

    $ fosr

# Generation modes

Two generation modes are available.

## Create-pcap

In this mode, Fos-R output a pcap file generated with the AI models.

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

If you need a deterministic generation, make sure to specify a seed with `-s`, to use `--order-pcap` and to set a start time with `-t`.

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

# Roadmap

## v0.2 - Reproducible and evaluated generation

A high-quality generation with end-to-end evaluation

## v0.3 - Fos-R library, GUI and generation portability

A GUI for Fos-R, cross-compilation (generation only) for most platforms, including WASM, and a library

## v0.4 - High-throughput network injection

A version focused on high-throughput network injection with low-level programming

# Technical description

The generation is organized in five stages.

- Stage 0: timestamp generation. This steps selects the starting point of the next flow to generate.
- Stage 1: netflow generation. This step relies on a Bayesian network to generate flows.
- Stage 2: intermediate representation generation. This step is based on the TADAM tool. Using the flows generated by stage 1, it creates a list of PacketsIR<T>, where T is a transport protocol. Each PacketsIR<T> corresponds to a flow between two IP addresses. This structure contains the original flow (generated by stage 1) with the metadata of the flow. There is also a vector packets_info that contains some information about the packet header: packet direction (forward or backward), payload size and type, timestamp, and TCP flags when the transport protocol is TCP.
- Stage 3: packet generation. Stage 3 creates a list of complete packets by completing the information given by the output of stage 2.
- Stage 4 (optional): send and receive packets on the network. Stage 4 relies on raw sockets to send and receive the packets generated by stage 3.

# Related publications

- Schoen, A., Blanc, G., Gimenez, P. F., Han, Y., Majorczyk, F., & Mé, L. (2024). A Tale of Two Methods: Unveiling the limitations of GAN and the Rise of Bayesian Networks for Synthetic Network Traffic Generation. In Proceedings of the 9th International Workshop on Traffic Measurements for Cybersecurity (WTMC 2024).
- Cüppers, J., Schoen, A., Blanc, G. & Gimenez, P. F., (2024, December). FlowChronicle: Synthetic Network Flow Generation through Pattern Set Mining Generation. In the 20th International Conference on emerging Networking EXperiments and Technologies (CoNEXT).
- Cornanguer, L. & Gimenez, P. F., (2025 May). TADAM: Learning Timed Automata From Noisy Observations. In the SIAM International Conference on Data Mining (SDM25).
- Gimenez, P. F., (2025). Synthetic Network Traffic Generation for Intrusion Detection Systems: a Systematic Literature Review. In the ESORICS 2025 International Workshops.
