# Forger Of Security Records

FosR is a software to generate synthetic network activity using AI. It relies on training data to learn user and software behavior so it can generate realistic and diverse data.

FosR is structured in two phases:
- the learning phase (in Python), that should be run once and requires input pcap data ;
- the generation phase (in Rust), that can generate data from the models learned in the first phase.

## Requirements

To run this repository, you will need:
- python3
- rustc

_In future versions, we will propose learned models and compiled binaries._

## How to use

Two steps:
- copy your pcap in the `data` folder
- call the script `./extract_learn_generate.sh data/your_file.pcap`

The learning phase can take a few days!

# Science: how does it work?

## Learning phase



## Generation phase
