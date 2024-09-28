#!/usr/bin/bash
# bash is necessary to take advantages of arrays

# mkdir -p tcp_flows

# PcapSplitter -f $1 -o tcp_flows -m connection -i tcp # split the streams (TCP only)

if [ "$OUTPUT_FILE" = "" ]; then outfile="output.csv"; else outfile=$OUTPUT_FILE; fi
id=0
echo protocol,src_ip,dst_ip,dst_port,fwd_packets,bwd_packets,fwd_bytes,bwd_bytes,time_sequence,payloads > $outfile
for file in tcp_flows/*; do
    echo "Process file $file"
    # TODO: add flow timestamp
    src_ip=""
    fwd_packets=0
    bwd_packets=0
    fwd_bytes=0
    bwd_bytes=0
    total_time=0
    protoname=""
    timeseq=""
    payloads=""
    error=0
    # order of the parameters is very important so TCP and UDP fields have the same array index. Payload can be empty so it’s at the end.
    # tshark -i - -T fields
    tshark -r $file -T fields \
        -e ip.proto -e ip.src -e ip.dst -e ip.ttl \
        -e tcp.time_delta -e tcp.dstport -e tcp.len -e tcp.flags.str -e tcp.payload \
        -e udp.time_delta -e udp.dstport -e udp.length -e udp.length -e udp.payload \
        -e icmp.type -e icmp.code -e data.len -e data | { while read l; do
        if [ "$((fwd_packets+bwd_packets))" -eq 300 ]; then
            echo "Dropping flow: too many packets"
            error=1
            break
        fi
        array=($l)
        proto=${array[0]}
        if [ "$proto" -eq 6 ] || [ "$proto" -eq 17 ]; then
            delta=$(echo "${array[4]}*1000000 / 1" | bc) # extract the time delta (unit: microsecond)
            ip=${array[1]} # extract the source IP (for direction identification)
            len=${array[6]} # extract the paquet length
            payloads=$payloads"P:"${array[8]}" " # extract payload (ensure it can not be empty)
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
            # output new letter (ensure it can not be empty)
            if [ "$proto" -eq 6 ]; then
                protoname="TCP"
                flags=$(echo ${array[7]} | tr -d "·") # specific to TCP
                timeseq=$timeseq$flags/$dir/$delta/$len" "
            elif [ "$proto" -eq 17 ]; then
                protoname="UDP"
                timeseq=$timeseq$dir/$delta/$len" "
            fi
        elif [ "$proto" -eq 1 ]; then
            protoname="ICMP"
            type=${array[4]}
            code=${array[5]}
            len=${array[6]}
            timeseq=$timeseq$type/$code/$len" "
            payloads=$payloads"P:"${array[7]}" " # extract payload (ensure it can not be empty)
        else
            echo "Unknown protocol ("$proto"), packed dropped"
        fi
        # id=$((id+1))
        # echo $id packets processed
    done
    if [ "$error" -eq 0 ]; then
        echo $protoname","$src_ip","$dst_ip","$dst_port","$fwd_packets","$bwd_packets","$fwd_bytes","$bwd_bytes","$timeseq","$payloads >> $outfile
    fi
    }
done
