#!/usr/bin/bash
# bash is necessary to take advantages of arrays

if [ "$1" = "" ]; then echo "Usage: $0 pcap-folder [output_file]"; exit; fi
outfile=$2
if [ "$outfile" = "" ]; then outfile="output.csv"; fi

echo timestamp,duration,protocol,src_ip,dst_ip,dst_port,fwd_packets,bwd_packets,fwd_bytes,bwd_bytes,time_sequence,payloads > $outfile
for file in $1/*; do
    # echo "Extract features from $file"
    timestamp=""
    last_time=""
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
    # udp.checksum is only here for padding (there cannot be twice the same field)
    tshark -r $file -T fields \
        -e frame.time_epoch \
        -e ip.proto -e ip.src -e ip.dst -e ip.ttl -e ip.frag_offset \
        -e tcp.time_delta -e tcp.dstport -e tcp.len -e tcp.flags.str -e tcp.payload \
        -e udp.time_delta -e udp.dstport -e udp.length -e udp.checksum -e udp.payload \
        -e icmp.type -e icmp.code -e data.len -e data | { while read l; do
        if [ "$((fwd_packets+bwd_packets))" -eq 250 ]; then
            echo "Skipping flow: too many packets ($file)"
            error=1
            break
        fi
        array=($l)
        proto=${array[1]}
        if [ "${array[5]}" -gt 0 ]; then
            echo "Skipping flow: fragmented packet ($file)"
            error=1
            break
        fi
        if [ "$timestamp" = "" ]; then
            timestamp=${array[0]}
        fi
        last_time=${array[0]}
        if [ "$proto" -eq 6 ] || [ "$proto" -eq 17 ]; then
            delta=$(echo "${array[6]}*1000000 / 1" | bc) # extract the time delta (unit: microsecond)
            ip=${array[2]} # extract the source IP (for direction identification)
            len=${array[8]} # extract the paquet length
            payloads=$payloads"P:"${array[10]}" " # extract payload (ensure it cannot be empty)
            if [ "$src_ip" = "" ]; then
                src_ip=$ip # extract only once destination IP and ports
                dst_ip=${array[3]}
                dst_port=${array[7]}
            fi # memorize first IP source
            # maybe use the file name to get the source IP?
            if [ "$src_ip" = "$ip" ]; then # infer direction
                dir=">"
                fwd_packets=$((fwd_packets+1))
                fwd_bytes=$((fwd_bytes+len))
                fwd_ttl=${array[4]}
            else
                dir="<"
                bwd_packets=$((bwd_packets+1))
                bwd_bytes=$((bwd_bytes+len))
                bwd_ttl=${array[4]}
                total_time=$((total_time+delta))
            fi
            # output new letter (ensure it can not be empty)
            if [ "$proto" -eq 6 ]; then
                protoname="TCP"
                flags=$(echo ${array[9]} | tr -d "·") # specific to TCP
                timeseq=$timeseq$flags/$dir/$delta/$len" "
            elif [ "$proto" -eq 17 ]; then
                protoname="UDP"
                timeseq=$timeseq$dir/$delta/$len" "
            fi
        elif [ "$proto" -eq 1 ]; then
            protoname="ICMP"
            type=${array[6]}
            code=${array[7]}
            len=${array[8]}
            timeseq=$timeseq$type/$code/$len" "
            payloads=$payloads"P:"${array[9]}" " # extract payload (ensure it can not be empty)
        else
            echo "Unknown protocol ("$proto"), packed dropped"
        fi
    done
    # trim
    timeseq=$(echo $timeseq | xargs)
    payloads=$(echo $payloads | xargs)
    if [ "$error" -eq 0 ]; then
        echo $timestamp,$(echo "($last_time-$timestamp)*1000000 / 1" | bc),$protoname","$src_ip","$dst_ip","$dst_port","$fwd_packets","$bwd_packets","$fwd_bytes","$bwd_bytes","$timeseq","$payloads >> $outfile
    fi
    }
done

echo "Most common ports:"
len=$(cat $outfile | wc -l)
thr=$((len/1000))
cat $outfile| tail -n +2 | cut -f6 -d, | sort | uniq -cd | awk -v limit=$thr '$1 > limit{print $2}'
