#!/usr/bin/bash

extract=0
fc_learn=0
tadam_learn=0
generate=0

while test $# -gt 0
do
    case "$1" in
        --force-extraction) extract=1
            ;;
        --force-pattern-learning) fc_learn=1
            ;;
        --force-automata-learning) tadam_learn=1
            ;;
        --force-generation) generate=1
            ;;
        --*) echo "Bad option $1"
            ;;
        *) if [ -n "$input" ]; then echo "At most one pcap file!"; exit; fi; input=$1
            ;;
    esac
    shift
done

if [ "$input" = "" ]; then echo "Usage: $0 [--force-extraction] [--force-pattern-learning] [--force-automata-learning] [--no-generation] file.pcap"; exit; fi
name=$(basename $input)
name=${name::-5}

# Features extraction
if [ ! -f data/$name/flows.csv ] || [ "$extract" -eq 1 ]; then
    echo "Features extraction"
    start=$(date +%s)
    rm -rf data/$name
    mkdir -p data/$name
    features_extraction/pkt2flow $input -u -x -o data/$name
    features_extraction/flow2csv.sh data/$name/tcp_syn data/$name/flows.csv
    # TODO: the other folders as well
    end=$(date +%s)
    echo "Features extraction time: $(($end-$start)) seconds"
fi

# Pattern learning
if [ ! -f models/$name/patterns.json ] || [ "$fc_learn" -eq 1 ]; then
    echo "Flow patterns learning"
    start=$(date +%s)
    mkdir -p models/$name
    cd learning
    source env/bin/activate
    # python3 ./flowchronicle_learn.py --input ../data/$name/flows.csv --output ../models/$name/patterns.json
    cd ..
    end=$(date +%s)
    echo "Flow patterns learning time: $(($end-$start)) seconds"
fi

# Automata learning
if [ ! -d data/$name/tas ] || [ "$tadam_learn" -eq 1 ]; then
    echo "Protocol automata learning"
    start=$(date +%s)
    rm -rf data/$name/tas
    mkdir -p data/$name/tas
    cd learning
    source env/bin/activate
    output_dir="../models/$name/tas/"
    output_dot_dir="../models/$name/tas/"
    # declare -A dst_ports=(["20"]="ftp-data" ["21"]="ftp" ["22"]="ssh" ["23"]="telnet" ["25"]="smtp-25" ["53"]="dns" ["67"]="dhcp-67" ["68"]="dhcp-68" ["80"]="http" ["88"]="kerberos" ["110"]="pop3" ["119"]="nntp" ["123"]="ntp" ["139"]="netbios" ["143"]="imap" ["194"]="irc" ["389"]="ldap" ["443"]="https" ["445"]="smb" ["465"]="smtp-ssl" ["993"]="imap-ssl") # TODO
    declare -A dst_ports=(["21"]="ftp")
    for i in "${!dst_ports[@]}"; do
        echo "Learning automata for destination port $i"
        python3 ./learn_automaton.py --select_dst_port $i --input ../data/$name/flows.csv --output $output_dir${dst_ports[$i]}.json --output_dot $output_dot_dir${dst_ports[$i]}.dot --automaton_name ${dst_ports[$i]}
    done
    cd ..
    end=$(date +%s)
    echo "Protocol automata learning time: $(($end-$start)) seconds"
fi

# Generation
if [ ! -f data/$name/synthetic.pcap ] || [ "$generate" -eq 1 ]; then
    echo "Generation"
    start=$(date +%s)
    cd generation
    cargo run -r -- offline -o ../data/$name/synthetic.pcap -m ../data/$name
    end=$(date +%s)
    echo "Generation time: $(($end-$start)) seconds"
fi
