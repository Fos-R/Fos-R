# Forger Of Security Recordings

## Data preparation

Prepare a unique pcap file:

    mergecap *.pcap *.pcapng -w file.pcapng

Transform it into a pcap file and remove the pcapng file:

    tshark -F pcap -r file.pcapng -w file.pcap; rm file.pcapng

Extract the flows:

    ntlflowlyzer -c <(echo '{"pcap_file_address": "file.pcap","output_file_address": "flows.csv","number_of_threads": 12}')

## Learning (TODO)

Go to the learning folder:

    cd learning

Install dependencies:

    pip install -U requirements.txt

Learn patterns:

    (TODO)

Learn automata:

    (TODO)

## Generation (TODO)

Go to the generation folder:

    cd ../generation

You can start 

    cargo run models/patterns.json models/tas
