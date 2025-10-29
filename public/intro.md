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

- `iptables`: a method for network injection (Linux only)
- `ebpf`: a method for network injection (Windows and Linux) [default]

If you do not enable `iptables` or `ebpf`, Fos-R won’t be able to inject traffic on the network. Generation is always available.

## Stable binaries

The binaries of the last stable versions are stored on [GitHub](https://github.com/Fos-R/Fos-R/releases).

## Experimental binaries
