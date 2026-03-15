---
title: "CICIDS17 dataset"
author: "Pierre-François Gimenez"
description: "Documentation on the CICIDS17 dataset"
---

# Dataset description

[CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) is a dataset presented in the article [A detailed analysis of the cicids2017 data set](https://doi.org/10.1007/978-3-030-25109-3_9) by Sharafaldin et al.

The pcap files were downloaded from <https://cicresearch.ca/CICDataset/CIC-IDS-2017/>.

- cicids17-train is Monday-WorkingHours.pcap
- cicids17-eval is Tuesday-WorkingHours.pcap from 10:30 to 13:30 (extracted with `editcap -A "2017-07-04 13:30:00" -B "2017-07-04 16:30:00"` (because New Brunswick was at UTC-3 at that moment)
- cicids-reference is Tuesday-WorkingHours.pcap" (extracted with `editcap -A "2017-07-04 13:30:00" -B "2017-07-04 16:30:00"` (idem)

The pcap files were processed as follow:
- they have been ordered with `reordercap`
- duplicated packets were removed with the attached "remove_duplication.sh" script (that comes from <https://gitlab.inria.fr/mlanvin/crisis2022/>)
- vlan packets have been removed with tshark with the filter `not vlan`

