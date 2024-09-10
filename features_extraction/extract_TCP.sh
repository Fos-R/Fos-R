#!/usr/bin/zsh

# TODO: convert to sh

# mkdir -p tcp_flows

# PcapSplitter -f $1 -o tcp_flows -m connection -i tcp # split the streams (TCP only)

file="tcp_flows/test.pcap"
outfile="tcp.csv"
# for file in tcp_flows/*; do
    id=0
    # for all streams
    src_ip=""
    dst_ip=""
    dst_port=""
    fwd_packets=0
    bwd_packets=0
    fwd_bytes=0
    bwd_bytes=0
    fwd_ttl=0
    bwd_ttl=0
    total_time=0
    protoname=""
    output=""
    flow=""
    tshark -r $file -T fields \
     -e ip.proto -e tcp.flags.str -e tcp.time_delta -e ip.src -e ip.dst \
     -e tcp.dstport -e ip.ttl -e tcp.len -e tcp.payload -e udp.dstport \
     -e udp.length -e udp.time_delta -e udp.payload | while read l; do
        # for all paquets
        proto=$(echo $l | cut -f 1)
        if [[ -z $proto ]]; then
            echo "Packet pas IP: drop"
        elif [[ $proto == "6" ]]; then
            echo "Packet TCP"
            protoname="TCP"
            flags=$(echo $l | cut -f 2 | tr -d "·") # extract flags (remove the ·)
            delta=$(echo $l | cut -f 3)
            delta=$(printf %.0f $((delta*100000))) # extract the time delta (unit: microsecond)
            ip=$(echo $l | cut -f 4) # extract the source IP (for direction identification)
            len=$(echo $l | cut -f 8) # extract the paquet length
            payload=$(echo $l | cut -f 9) # extract the payload
            if [[ -z $src_ip ]]; then
                src_ip=$ip # extract only once destination IP and ports
                dst_ip=$(echo $l | cut -f 5)
                dst_port=$(echo $l | cut -f 6)
            fi # memorize first IP source
            # maybe use the file name to get the source IP?
            if [[ $src_ip == $ip ]]; then # infer direction
                dir=">"
                fwd_packets=$((fwd_packets+1))
                fwd_bytes=$((fwd_bytes+len))
                fwd_ttl=$(echo $l | cut -f 7)
            else
                dir="<"
                bwd_packets=$((bwd_packets+1))
                bwd_bytes=$((bwd_bytes+len))
                bwd_ttl=$(echo $l | cut -f 7)
            total_time=$((total_time+delta))
            fi
            output=$output$flags/$delta/$dir/$payload" " # output new letter
        elif [[ $proto == "17" ]]; then
            echo "Packet UDP"
            protoname="UDP"
            delta=$(echo $l | cut -f 12)
            delta=$(printf %.0f $((delta*100000))) # extract the time delta (unit: microsecond)
            ip=$(echo $l | cut -f 4) # extract the source IP (for direction identification)
            len=$(echo $l | cut -f 11) # extract the paquet length
            payload=$(echo $l | cut -f 13) # extract the payload
            if [[ -z $src_ip ]]; then
                src_ip=$ip # extract only once destination IP and ports
                dst_ip=$(echo $l | cut -f 5)
                dst_port=$(echo $l | cut -f 10)
            fi # memorize first IP source
            # maybe use the file name to get the source IP?
            if [[ $src_ip == $ip ]]; then # infer direction
                dir=">"
                fwd_packets=$((fwd_packets+1))
                fwd_bytes=$((fwd_bytes+len))
                fwd_ttl=$(echo $l | cut -f 7)
            else
                dir="<"
                bwd_packets=$((bwd_packets+1))
                bwd_bytes=$((bwd_bytes+len))
                bwd_ttl=$(echo $l | cut -f 7)
            total_time=$((total_time+delta))
            fi
            output=$output$delta/$dir/$payload" " # output new letter
        elif [[ $proto == "1" ]]; then
            echo "Packet ICMP: TODO"
        fi

    done
    # dstport=$(echo $file | rev | cut -f 1 -d_ | rev | cut -f 1 -d .) # get destination port from file name (more robust)
    flock $outfile echo $protoname","$src_ip","$dst_ip","$fwd_packets","$bwd_packets","$fwd_bytes","$bwd_bytes","$output >> $outfile
# done
