# Network file

To use the "create-pcap" command, you must provide a network file that describe the network you want to generate data for.

Here is a minimal network file with a user (IP address: 192.168.0.9) and a server (IP address: 192.168.0.8) which provides two services: an SSH server (on port 2222) and an HTTP server.

```yaml
metadata:
  title: Sample network
hosts:
  - interfaces:
      - ip_addr: 192.168.0.8
        services:
          - http
          - ssh:2222
  - interfaces:
      - ip_addr: 192.168.0.9
```

Besides metadata, a network file consists of a list of hosts, which contain a list of interfaces.

The next example showcases the different available fields:

```yaml
metadata:
  title: Sample network # Mandatory. The name of the network.
  desc: A sample network file to show all the different available fields # Optional. A description of the network.
  author: Jane Doe # Optional. Author of the file.
  date: 2025/11/05 # Optional. Last modification date.
  version: 0.1.0 # Optional. The version number of this network file. Format is free.
  format: 1 # Reserved for now. The version will be bumped when the format changes.

hosts:
  - hostname: host1 # Optional. The hostname of the host.
    os: Linux # Optional (default value: Linux). The OS of the host
    type: server  # Optional (default value: "server" if there is at least one service, "user" otherwise). Whether this host is used by a user and is a server. Can be either "server" or "user"
    interfaces:
      - mac_addr: 00:14:2A:3F:47:D8 # Optional. The MAC address of that interface
        services: # Optional (default value: empty list). The list of available services
          - http:8080 # an HTTP server on port 8080
          - https     # an HTTPS server
          - ssh       # an SSH server
        ip_addr: 192.168.0.8 # Mandatory. The IP address of this interface.
      - ip_addr: 192.168.0.9 # This host has another interface that does not provide any service
  - interfaces:
      - ip_addr: 192.168.0.11 # Another host with a single interface
```

This format is still experimental and may change in a next version.
