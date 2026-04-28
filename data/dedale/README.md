---
title: "CUPID dataset"
author: "Pierre-François Gimenez"
description: "Documentation on the CUPID dataset"
---

# Dataset description

[DEDALE](https://dedale.inria.fr/) is a dataset presented in the article [Get out of DEDALE with RESCOUSSE: a New Dataset and Testbed for Evaluating the Detection of APT attacks among Network and System Logs](https://hal.science/hal-05329482/) by Lanvin et al.

The pcap files were downloaded from <https://dedale.inria.fr/>. We split the file `D1_2024-12-23_output_green_internal.pcap` in three:
- dedale-train has been extracted with `editcap -A "2024-12-23 10:00:00" -B "2024-12-23 11:00:00"`
- dedale-eval has been extracted with `editcap -A "2024-12-23 11:00:00" -B "2024-12-23 12:00:00"`
- dedale-reference has been extracted with `editcap -A "2024-12-23 12:00:00" -B "2024-12-23 13:00:00"`

The pcap files are already temporally ordered and contain no vlan packets, no so further processing were performed.

The timezone of the dataset is UTC+1.
