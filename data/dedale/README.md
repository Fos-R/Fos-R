---
title: "CUPID dataset"
author: "Pierre-François Gimenez"
description: "Documentation on the CUPID dataset"
---

# Dataset description

[DEDALE](https://dedale.inria.fr/) is a dataset presented in the article [Get out of DEDALE with RESCOUSSE: a New Dataset and Testbed for Evaluating the Detection of APT attacks among Network and System Logs](https://hal.science/hal-05329482/) by Lanvin et al.

The pcap files were downloaded from <https://dedale.inria.fr/>.

- dedale-train is `D1_2024-12-23_output_green_internal.pcap`
- dedale-eval has been extracted with `editcap -A "2024-12-24 00:00:00" -B "2024-12-24 12:00:00" D2_2024-12-24_output_green_internal.pcap`
- dedale-reference has been extracted with `editcap -A "2024-12-24 12:00:00" -B "2024-12-25 00:00:00" D2_2024-12-24_output_green_internal.pcap`
- dedale-data-augmentation has been extracted from all days with attacks, i.e., D15, D17, D19, D20, D21 and D22.

The pcap files are already temporally ordered and contain no vlan packets, no so further processing were performed.

The timezone of the dataset is UTC+1.
