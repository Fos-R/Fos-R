#!/usr/bin/env bash
# We build three fake machines on this computer, chained like this:
#
#   [left]  veth-l 10.0.1.2 ── dut-l 10.0.1.1  [dut]  dut-r 10.0.2.1 ── veth-r 10.0.2.2  [right]
#    Fos-R                          forwards packets                           Fos-R
#
set -euo pipefail

FOSR=${FOSR:-./target/release/fosr-cli}
CAPTURE=${CAPTURE:-across.pcap}

setup() {
    sudo ip netns add left
    sudo ip netns add dut
    sudo ip netns add right

    sudo ip link add veth-l netns left type veth peer name dut-l netns dut
    sudo ip link add veth-r netns right type veth peer name dut-r netns dut

    sudo ip -n left  addr add 10.0.1.2/24 dev veth-l
    sudo ip -n dut   addr add 10.0.1.1/24 dev dut-l
    sudo ip -n dut   addr add 10.0.2.1/24 dev dut-r
    sudo ip -n right addr add 10.0.2.2/24 dev veth-r

    sudo ip -n left  link set veth-l up
    sudo ip -n dut   link set dut-l up
    sudo ip -n dut   link set dut-r up
    sudo ip -n right link set veth-r up
    for ns in left dut right; do
        sudo ip -n "$ns" link set lo up
    done

    sudo ip netns exec dut sysctl -q -w net.ipv4.ip_forward=1

    sudo ip -n left  route add default via 10.0.1.1
    sudo ip -n right route add default via 10.0.2.1

    sudo ip netns exec left ping -c3 10.0.2.2
}

run() {
    sudo -v

    sudo ip netns exec dut tcpdump -ni dut-l -w "$CAPTURE" &
    sleep 1

    sudo ip netns exec left "$FOSR" inject-across -m ccd -n crates/fosr-lib/default_topologies/lab-across.yaml \
        -s 42 -d 2min -o left.pcap &
    local left_pid=$!
    sudo ip netns exec right "$FOSR" inject-across -m ccd -n crates/fosr-lib/default_topologies/lab-across.yaml \
        -s 42 -d 2min -o right.pcap &
    local right_pid=$!

    wait "$left_pid" "$right_pid"
    sleep 2

    sudo pkill -INT -f "^tcpdump -ni dut-l" || true
    wait

    sudo chown "$(id -u):$(id -g)" "$CAPTURE" left.pcap right.pcap
}

clean() {
    for ns in left dut right; do
        sudo ip netns del "$ns" 2>/dev/null || true
    done
}

setup
run
clean
