# Changelog

## [Unreleased]

### Added

- Honeynet can be seeded too

### Changed

- IPTables rules are more specific to avoid interacting with normal communications

## v0.1.0

First available version of Fos-R. This version has been used for the BreizhCTF’25 competition.

### Added

- Support of IPv4 TCP packets only
- Support for Linux only
- Offline generation of pcap files (augmentation only)
- Honeynet mode
- Default model: hand-written FlowChronicle model for BreizhCTF’25
- Default model: automata for protocols HTTP, HTTPS, SSH, SMTP and MQTT
