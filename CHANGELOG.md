# Changelog

## Unreleased

### Added

- Better library documentation
- Option for monothreaded generation

### Changed

- "stage4" module renamed to "inject"
- Bugfixes

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
