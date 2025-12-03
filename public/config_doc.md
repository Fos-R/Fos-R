# Configuration file

By default, Fos-R generates traffic that is similar to its learning data. The main way to customize the generated data is through a configuration file. This configuration file allows to describe the hosts of a network.

Here is a minimal configuration file with a user (IP address: 192.168.0.9) and a server (IP address: 192.168.0.8) which provides two services: an SSH server (on port 2222) and an HTTPS server.

```yaml
metadata:
  title: Sample configuration
hosts:
  - interfaces:
      - ip_addr: 192.168.0.8
        services:
          - https
          - ssh:2222
  - interfaces:
      - ip_addr: 192.168.0.9
```

Besides metadata, a configuration file consists of a list of hosts, which contain a list of interfaces. *For the moment, Fos-R cannot properly simulate the routing of packets, so the IP addresses should be the same subnet*.

The next example showcases the different available fields:

```yaml
metadata:
  title: Sample configuration # Mandatory. The title of the configuration file.
  desc: A sample configuration file to show all the different available fields # Optional. A description of the configuration file.
  author: Jane Doe # Optional. Author of the file.
  date: 2025/11/05 # Optional. Last modification date.
  version: 0.1.0 # Optional. The version number of this configuration file. Format is free.
  format: 1 # Reserved for now. The version will be bumped when the format changes.

hosts:
  - hostname: host1 # Optional. The hostname of the host.
    os: Linux # Optional (default value: Linux). The OS of the host
    usage: 0.8 # Optional (default value: 1.0). The usage intensity of the host. 1 is the baseline, < 1 means less usage than usual, and > 1 means higher usage
    type: server  # Optional (default value: "server" if there is at least one service, "user" otherwise). Whether this host is used by a user and is a server. Can be either "server" or "user"
    client: # Optional (default value: all available services if type is "user", none otherwise). Specify what services the host is a client of. The protocols must be written in lowercase.
        - http
        - https
        - ssh
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

You can also use a JSON file with a similar structure.

This format is still experimental and we are willing to extend it to handle more use cases.
