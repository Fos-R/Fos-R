#!/usr/bin/bash

extract=1
learn=1
generate=1

while test $# -gt 0
do
    case "$1" in
        --no-extraction) extract=0
            ;;
        --no-learning) learn=0
            ;;
        --no-generation) generate=0
            ;;
        --*) echo "Bad option $1"
            ;;
        *) if [ -n "$input" ]; then echo "At most one pcap file!"; exit; fi; input=$1
            ;;
    esac
    shift
done

if [ "$input" = "" ]; then echo "Usage: $0 [--no-extraction] [--no-learning] [--no-generation] file.pcap"; exit; fi
name=$(basename $input)
name=${name::-5}

# Features extraction
if [ "$extract" -eq 1 ]; then
    echo "Features extraction"
    rm -rf features_extraction/flows_$name
    features_extraction/pkt2flow $input -u -x -o features_extraction/flows_$name
    cd features_extraction
    ./flow2csv.sh flows_$name/tcp_syn ../data/$name.csv
    # TODO: the other folders as well
    cd ..
fi

# Learning
if [ "$learn" -eq 1 ]; then
    echo "Learning"
    cd learning
    source env/bin/activate
    # python3 ./flowchronicle_learn.py --input ../data/$name.csv --output ../models/"$name"_patterns.json
    output_dir="../models/tas/"
    output_dot_dir="../models/tas/"
    declare -A dst_ports=(["21"]="ftp" ["443"]="https") # TODO: complete
    # declare -A dst_ports=(["21"]="ftp") # TODO: complete
    for i in "${!dst_ports[@]}"; do
        python3 ./learn_automaton.py --select_dst_port $i --input ../data/$name.csv --output $output_dir${dst_ports[$i]}.json --output_dot $output_dot_dir${dst_ports[$i]}.dot --automaton_name ${dst_ports[$i]}
    done
    cd ..
fi

# Generation
if [ "$generate" -eq 1 ]; then
    echo "Learning"
    cd generation
    cargo run -r # TODO
fi
