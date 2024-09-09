# Forger Of Security Recordings

## Data preparation

Prepare a unique pcap file:

    mergecap *.pcap *.pcapng -w file.pcapng

Transform it into a pcap file and remove the pcapng file:

    tshark -F pcap -r file.pcapng -w file.pcap; rm file.pcapng

Extract the flows:

    ntlflowlyzer -c <(echo '{"pcap_file_address": "file.pcap","output_file_address": "flows.csv","number_of_threads": 12}')

## Learning (TODO)

FlowChronicle with netflows

TADAM : one automata per dest port + UDP + ICMP

## Generation (TODO)

    cargo run patterns.json tas
