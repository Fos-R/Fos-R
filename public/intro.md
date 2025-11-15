---
title: "Fos-R, the synthetic network traffic generator"
author: "Pierre-François Gimenez"
description: "A network synthetic traffic generator"
---

![](logo.png)

<center>
<img style="width: auto" src="https://img.shields.io/crates/v/fosr.svg?color=brightgreen&style=flat-square">
<img style="width: auto" src="https://img.shields.io/crates/d/fosr?label=downloads%20%28crates.io%29&style=flat-square">
<img style="width: auto" src="https://img.shields.io/badge/license%2FGPLv3-blue?style=flat-square">
<img style="width: auto" src="https://gitlab.inria.fr/pirat-public/Fos-R/badges/main/pipeline.svg">
</center>

[![pipeline status]()](https://gitlab.inria.fr/pirat-public/Fos-R/-/commits/main) 
Fos-R is a network traffic generator based on AI models. It does not require a GPU and can generate in the order of Gbps of network traffic with a laptop.

# Get Fos-R

## Cargo features

Fos-R make use of Cargo features for conditional compilation. The available features:

- `iptables`: a method for network injection (Linux only)
- `ebpf`: a method for network injection (Windows and Linux) [default]

If you do not enable `iptables` or `ebpf`, Fos-R won’t be able to inject traffic on the network. Generation is always available.

## Stable binaries

The binaries of the last stable versions are stored on [GitHub](https://github.com/Fos-R/Fos-R/releases).

## Experimental binaries
