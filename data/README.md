# Data directory

There is a folder per dataset. Each folder contains a short description of the dataset and how the pcap files were obtained and processed.
For each dataset D, such folder contains three more folders:

- `D-train` contains the data available for training
- `D-eval` contains the data to compare to
- `D-reference` contains real data and serves as a baseline during evaluation

Prior to learning Fos-R models and evaluating generation methods, the pcap files should be processed.
There are two shell scripts:

- `feature-extraction.sh` is for extracting the features prior to learning. It should be called from \*-train folders.
- `pcap-analysis.sh` is for the evaluation of the distance between pcaps. It should be called from the other folders.

