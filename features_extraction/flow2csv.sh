#!/usr/bin/sh

# mkdir -p tcp_flows

# PcapSplitter -f $1 -o tcp_flows -m connection -i tcp # split the streams (TCP only)

file="chat.pcap"
if [ "$OUTPUT_FILE" = "" ]; then outfile="output.csv"; else outfile=$OUTPUT_FILE; fi
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
    # tshark -i - -T fields
    tshark -r $file -T fields \
     -e ip.proto -e tcp.flags.str -e tcp.time_delta -e ip.src -e ip.dst \
     -e tcp.dstport -e ip.ttl -e tcp.len -e tcp.payload -e udp.dstport \
     -e udp.length -e udp.time_delta -e udp.payload | while read l; do
        # for all paquets
        proto=$(echo $l | cut -f 1 -d " ")
        if [ "$proto" = "" ]; then
            :
        elif [ "$proto" -eq 6 ]; then
            protoname="TCP"
            flags=$(echo $l | cut -f 2 -d " " | tr -d "·") # extract flags (remove the ·)
            delta=$(echo $l | cut -f 3 -d " ")
            delta=$(printf %.0f $(echo "$delta*1000000" | bc -l)) # extract the time delta (unit: microsecond)
            ip=$(echo $l | cut -f 4 -d " ") # extract the source IP (for direction identification)
            len=$(echo $l | cut -f 8 -d " ") # extract the paquet length
            payload=$(echo $l | cut -f 9 -d " ") # extract the payload
            if [ "$src_ip" = "" ]; then
                src_ip=$ip # extract only once destination IP and ports
                dst_ip=$(echo $l | cut -f 5 -d " ")
                dst_port=$(echo $l | cut -f 6 -d " ")
            fi # memorize first IP source
            # maybe use the file name to get the source IP?
            if [ "$src_ip" = "$ip" ]; then # infer direction
                dir=">"
                fwd_packets=$((fwd_packets+1))
                fwd_bytes=$((fwd_bytes+len))
                fwd_ttl=$(echo $l | cut -f 7 -d " ")
            else
                dir="<"
                bwd_packets=$((bwd_packets+1))
                bwd_bytes=$((bwd_bytes+len))
                bwd_ttl=$(echo $l | cut -f 7 -d " ")
            total_time=$((total_time+delta))
            fi
            output=$output$flags/$delta/$dir/$payload" " # output new letter
        elif [ "$proto" -eq 17 ]; then
            protoname="UDP"
            delta=$(echo $l | cut -f 12 -d " ")
            delta=$(printf %.0f $((delta*100000))) # extract the time delta (unit: microsecond)
            ip=$(echo $l | cut -f 4 -d " ") # extract the source IP (for direction identification)
            len=$(echo $l | cut -f 11 -d " ") # extract the paquet length
            payload=$(echo $l | cut -f 13 -d " ") # extract the payload
            if [ "$src_ip" = "" ]; then
                src_ip=$ip # extract only once destination IP and ports
                dst_ip=$(echo $l | cut -f 5 -d " ")
                dst_port=$(echo $l | cut -f 10 -d " ")
            fi # memorize first IP source
            # maybe use the file name to get the source IP?
            if [ "$src_ip" = "$ip" ]; then # infer direction
                dir=">"
                fwd_packets=$((fwd_packets+1))
                fwd_bytes=$((fwd_bytes+len))
                fwd_ttl=$(echo $l | cut -f 7 -d " ")
            else
                dir="<"
                bwd_packets=$((bwd_packets+1))
                bwd_bytes=$((bwd_bytes+len))
                bwd_ttl=$(echo $l | cut -f 7 -d " ")
            total_time=$((total_time+delta))
            fi
            output=$output$delta/$dir/$payload" " # output new letter
        elif [ "$proto" -eq 1 ]; then
            :
        fi
        id=$((id+1))
        echo $id packets processed
    done
    # dstport=$(echo $file | rev | cut -f 1 -d_ | rev | cut -f 1 -d .) # get destination port from file name (more robust)
    flock $outfile echo $protoname","$src_ip","$dst_ip","$dst_port","$fwd_packets","$bwd_packets","$fwd_bytes","$bwd_bytes","$output >> $outfile
# done
