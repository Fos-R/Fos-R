# Forger Of Security Records

FosR is a software to generate synthetic network activity using AI. It relies on training data to learn user and software behavior so it can generate realistic and diverse data.

FosR is structured in two phases:
- the learning phase (in Python), that should be run once and requires input pcap data ;
- the generation phase (in Rust), that can generate data from the models learned in the first phase.

## Requirements

To run this repository, you will need:
- python3
- pip
- rustc
- libpcap

_In future versions, we will propose learned models and compiled binaries._

## How to use

Two steps:
- copy your pcap in the `data` folder
- call the script `./extract_learn_generate.sh data/your_file.pcap`

The learning phase can take a few days!

## Using the test environment

Install Vagrant and a virtual machine provider for vagrant (e.g. Virtualbox or libvirt):
```sh
cd
vagrant up
```

You can then access the virtual machines and start fosr with:
```sh
vagrant ssh vm1 # or vm2
cd fosr
sudo ./target/release/fosr honeynet -t -c vagrant.toml
```

And gather the communications in a second terminal:
```sh
vagrant ssh vm1
cd fosr
sudo tcpdump -i eth1 -w test.pcap
```

The `test.pcap` file would then be available on the host machine in the `generation` folder.

# Science: how does it work?

## Learning phase



## Generation phase
