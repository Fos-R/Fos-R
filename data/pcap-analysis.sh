#!/bin/sh
if [ -f "data.pcap" ]; then
    echo "Zeek analysis"
    zeek -C -r data.pcap
    echo "TShark analysis"
    tshark -c 5000000 -r data.pcap -T fields -E header=y -E separator=, -E occurrence=f -e ip.len -e ip.ttl -e ip.src -e ip.dst -e ip.proto "eth.type == 0x0800" > ip.csv
    tshark -c 5000000 -r data.pcap -T fields -E header=y -E separator=, -E occurrence=f -e tcp.flags "ip.proto == 6" > tcp.csv
    tshark -c 5000000 -r data.pcap -z expert,warn -q > expert_info.txt
    echo "Suricata analysis"
    suricata -c /etc/suricata/suricata.yaml -r data.pcap > suricata.txt
else
    echo "Call this script from a directory containing data.pcap"
fi
