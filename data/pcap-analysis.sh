#!/bin/sh
# This script is used to extract data for evaluation purposes

if [ -f "data.pcap" ]; then
    echo "Zeek analysis"
    zeek -C -r data.pcap
    echo "TShark analysis"
    tshark -c 5000000 -r data.pcap -T fields -E header=y -E separator=, -E occurrence=f -e ip.len -e ip.ttl -e ip.src -e ip.dst -e ip.proto "eth.type == 0x0800" > ip.csv
    tshark -c 5000000 -r data.pcap -T fields -E header=y -E separator=, -E occurrence=f -e tcp.flags "ip.proto == 6" > tcp.csv
    tshark -c 5000000 -r data.pcap -z expert,warn -q > expert_info.txt
    echo "Suricata analysis"
    # suricata-update should be run
    suricata -c /etc/suricata/suricata.yaml -S /var/lib/suricata/rules/suricata.rules -r data.pcap
    echo "Statistics:"
    weird=$(cat weird.log | grep -v '^#' | wc -l | cut -f1 -d" ")
    error=$(cat expert_info.txt| grep Errors | cut -f2 -d"(" | cut -f1 -d")")
    warn=$(cat expert_info.txt| grep Warns | cut -f2 -d"(" | cut -f1 -d")")
    alerts=$(cat suricata.log | grep Alerts | tail -n 1 | cut -f6 -d":")
    flow=$(cat conn.log | grep -v '^#' | wc -l)
    packets=$(capinfos data.pcap | grep " Number of packets" | cut -f2 -d"=")
    echo "  Error rate:" $(echo "100 * $error / $packets" | bc -l)%
    echo "  Warn rate:" $(echo "100 * $warn / $packets" | bc -l)%
    echo "  Weird rate:" $(echo "100 * $weird / $flow" | bc -l)%
    echo "  Alert rate:" $(echo "100 * $alerts / $packets" | bc -l)%
else
    echo "Call this script from a directory containing data.pcap"
fi
