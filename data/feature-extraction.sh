#!/bin/sh
# This script is used to extract feature prior to Fos-R model training

if [ -f "data.pcap" ]; then
    echo "Zeek analysis"
    zeek -C -r data.pcap ../../fosr_feature_extraction.zeek
else
    echo "Call this script from a directory containing data.pcap"
fi
