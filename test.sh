sudo ip link add veth0 type veth peer name veth1
sudo ip addr add 192.168.1.1/24 dev veth0
sudo ip addr add 192.168.1.2/24 dev veth1
sudo ip link set veth0 up
sudo ip link set veth1 up
