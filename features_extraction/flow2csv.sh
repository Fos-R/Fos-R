#!/usr/bin/bash
# bash is necessary to take advantages of arrays

# mkdir -p tcp_flows

# PcapSplitter -f $1 -o tcp_flows -m connection -i tcp # split the streams (TCP only)

file="chat.pcap"
if [ "$OUTPUT_FILE" = "" ]; then outfile="output.csv"; else outfile=$OUTPUT_FILE; fi
# for file in tcp_flows/*; do
id=0
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
# order of the parameters is very important so TCP and UDP fields have the same array index
# tshark -i - -T fields
tshark -r $file -T fields \
    -e ip.proto -e ip.src -e ip.dst -e ip.ttl \
    -e tcp.time_delta -e tcp.dstport -e tcp.len -e tcp.payload -e tcp.flags.str \
    -e udp.time_delta -e udp.dstport -e udp.length -e udp.payload | while read l; do
    array=($l)
    proto=${array[0]}
    if [ "$proto" -eq 6 ] || [ "$proto" -eq 17 ]; then
        delta=$(echo "${array[4]}*1000000 / 1" | bc) # extract the time delta (unit: microsecond)
        ip=${array[1]} # extract the source IP (for direction identification)
        len=${array[6]} # extract the paquet length
        payload=${array[7]} # extract payload
        if [ "$src_ip" = "" ]; then
            src_ip=$ip # extract only once destination IP and ports
            dst_ip=${array[2]}
            dst_port=${array[5]}
        fi # memorize first IP source
        # maybe use the file name to get the source IP?
        if [ "$src_ip" = "$ip" ]; then # infer direction
            dir=">"
            fwd_packets=$((fwd_packets+1))
            fwd_bytes=$((fwd_bytes+len))
            fwd_ttl=${array[3]}
        else
            dir="<"
            bwd_packets=$((bwd_packets+1))
            bwd_bytes=$((bwd_bytes+len))
            bwd_ttl=${array[3]}
            total_time=$((total_time+delta))
        fi
        # output new letter
        if [ "$proto" -eq 6 ]; then
            protoname="TCP"
            flags=$(echo ${array[8]} | tr -d "·") # specific to TCP
            output=$output$flags/$delta/$dir/$payload" "
        elif [ "$proto" -eq 17 ]; then
            protoname="UDP"
            output=$output$delta/$dir/$payload" "
        fi
    elif [ "$proto" -eq 1 ]; then
        protoname="ICMP"
    else
        echo "Unknown protocol ("$proto"), packed dropped"
    fi
    id=$((id+1))
    echo $id packets processed
done
flock $outfile echo $protoname","$src_ip","$dst_ip","$dst_port","$fwd_packets","$bwd_packets","$fwd_bytes","$bwd_bytes","$output >> $outfile
