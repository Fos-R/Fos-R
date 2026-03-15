---
title: "CUPID dataset"
author: "Pierre-François Gimenez"
description: "Documentation on the CUPID dataset"
---

# Dataset description

[CUPID](https://cupid.directory/) is a dataset presented in the article [CUPID: A labeled dataset with Pentesting for evaluation of network intrusion detection](https://doi.org/10.1016/j.sysarc.2022.102621) by Lawrence et al.

The pcap files were downloaded from <https://cupid.directory/>.

- cupid-train is 042219_1000.pcapng
- cupid-eval is 042319_1000.pcapng
- cupid-reference is 042419_1000.pcapng

The pcap files were processed as follow:
- they have been ordered with `reordercap`
- vlan packets have been removed with tshark with the filter `not vlan`
- the output format was set to pcap and not pcapng

