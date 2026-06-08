# Changelog

## Unreleased

### Added

#### fosr-lib

- New stage 1 with realistic time distribution
- New stage 2 with Bayesian networks
- New default models (CICIDS17, CUPID and DEDALE)

#### fosr-cli

- Crate `fosr` renamed to `fosr-cli`
- Faster (up to ~5x) generation
- Added `--tz` option and timezone support more generally
- Added `--jobs` option
- Two generation profiles: "fast" or "efficient" (can be "auto")

#### fosr

- New crate with an unstable GUI

#### other

- Evaluation pipeline
- Added a Zeek script for feature extraction
- TADAM: noise includes substitution
- TADAM: include payload types from tshark
- Reworked learning algorithms

### Changed

#### fosr-lib

- `fosr` crate split into `fosr-lib` and `fosr-cli`
- Stage renaming (0->1, 1->2, 2->3, 3->4)
- `stage4` module renamed to `inject`
- Created the `export` module
- Transformed panics into `Result`s
- Slight modification of automata json format
- Better library documentation
- Split `augment-dataset` and `create-pcap` subcommands
- Bugfixes

#### fosr-cli

- No network injection by default
- Pcap files are now sorted by default
- Bugfixes

### Removed

- Removed pcap2flow mode
- Removed `--packets-count`

## v0.1.2

### Added

- Windows support through eBPF
- New stage 0 with daily seasonality
- Pcap2flow mode
- Utility to remove Fos-R taint from pcap files
- Add the "fast" injection algorithm for higher throughput
- CI pipeline for continuous evaluation

### Changed

- Output for create-pcap can be deterministic (with the correct options)
- Bugfixes

## v0.1.1

### Added

- Crate includes a binary and a library
- Support of IPv4 UDP packets
- Default models: automata for protocols DNS and NTP
- Significantly reduced binary size by compressing default models
- Better documentation
- Bugfixes

### Changed

- IPTables rules are more specific to avoid interacting with normal communications
- Remove libpcap dependency

## v0.1.0

First available version of Fos-R. This version has been used for the BreizhCTF’25 competition.

### Added

- Support of IPv4 TCP packets only
- Support for Linux only
- Offline generation of pcap files (augmentation only)
- Honeynet mode
- Default model: hand-written FlowChronicle model for BreizhCTF’25
- Default models: automata for protocols HTTP, HTTPS, SSH, SMTP and MQTT
