# Configuration file

By default, Fos-R will generate traffic that is similar to its learning data. The main way to customize the generated data is through a configuration file. This configuration file allows to describe the hosts of a network.

Here is a minimal configuration file with a user (IP address: 192.168.0.9) and a server (IP address: 192.168.0.8) which provides two services: an SSH server and an HTTPS server.

```
hosts:
  - interfaces:
      - services:
          - https
          - ssh
        ip_addr: 192.168.0.8
  - interfaces:
      - ip_addr: 192.168.0.9
metadata:
  title: Sample configuration
```

Besides metadata, a configuration file consists of a list of hosts, which contain a list of interfaces. *For the moment, Fos-R cannot properly simulate the routing of packets, so you should IP addresses from the same subnet*.

## Fields

The next example showcases the different available fields:

```
hosts:
  - hostname: host1 # Optional. The hostname of the host.
    os: Linux # Optional (default value: Linux). The OS of the host
    activity: 0.8 # Optional (default value: 1.0). The activity level of the host. 1 is the baseline, < 1 means less activity than usual, and > 1 means higher activity
    type: server  # Optional (default value: "server" if there is at least one service, "user" otherwise). Whether this host is used by a user and is a server. Can be either "server" or "user"
    interfaces:
      - mac_addr: 00:14:2A:3F:47:D8 # Optional. the MAC address of that interface
        services: Optional (default value: empty list) The list of available services.
          - http  # an HTTP server
          - https # an HTTPS server
          - ssh   # an SSH server
        ip_addr: 192.168.0.8 # Mandatory. The IP address of this interface.
      - ip_addr: 192.168.0.9 # This host has another interface that do not provide any service
  - interfaces:
      - ip_addr: 192.168.0.11 # Another host with a single interface

metadata:
  author: Pierre-François Gimenez # Optional. Author of the file.
  date: 2025/11/05 # Optional. Last modification date.
  title: Sample configuration # Mandatory. The title of the configuration file.
  desc: A sample configuration file to show all the different available fields # Optional. A description of the configuration file.
  version: 0.1.0 # Optional. The version number of this configuration file. Format is free.
  format_version: 1 # Reserved. The version will be bumped if the format changes.
```

This format is still experimental and we are willing to extend it to handle more use cases.
