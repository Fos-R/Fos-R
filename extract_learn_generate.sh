#!/usr/bin/bash

if [ "$1" = "" ]; then echo "Usage: $0 file.pcap"; exit; fi
input=$1
name=$(basename $input)
name=${name::-5}

# Features extraction
echo "Features extraction"
echo "Splitting pcap file into flows"
features_extraction/pkt2flow $input -u -x -o features_extraction/flows_$name
cd features_extraction
./flow2csv.sh flows_$name/tcp_syn ../data/$name.csv
# TODO: the other folders as well

# Learning
cd learning
python3 ./flowchronicle_learn.py --input ../data/$name.csv --output ../models/"$name"_patterns
exit
./learn_all_automata.sh

# Generation
cd generation
cargo run -r # TODO
