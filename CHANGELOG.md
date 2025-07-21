# Changelog

## [Unreleased]

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
