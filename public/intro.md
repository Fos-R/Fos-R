---
title: "Fos-R, the synthetic network traffic generator"
author: "Pierre-François Gimenez"
description: "A network synthetic traffic generator"
---

![](logo.png)

Fos-R is a network traffic generator based on AI models. It does not require a GPU and can generate in the order of Gbps of network traffic with a laptop.

# Get Fos-R

## Conditional features

Fos-R make use of Rust features for conditional compilation. The available features:

- `net_injection`: whether the program can inject traffic on the network interface [default]
- `iptables`: a method for network injection (Linux only)
- `ebpf`: a method for network injection (Windows and Linux) [default]

Generation is always available.

## Stable binaries

The binaries of the last stable versions are stored on [GitLab](https://gitlab.inria.fr/pirat-public/Fos-R/-/releases).

## Experimental binaries
