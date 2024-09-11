import os
import argparse
import re
import json
from TADAM.TADAM import exhaustive_search, opportunistic_search
from TADAM.MDL import NoiseModel
from Options import Options, GuardsFormat, Init, Search
import pandas as pd
import datetime

def parse_TCP(input_string):
    """
        Contains: flags, direction, payload type, iat, payload size
    """
    if "$" in input_string: return "$", [0,0]
    match = re.match(r'([A-Za-z]+)/([><])/([A-Za-z]+)/(-?\d+.\d+)/(\d+)', input_string)
    if match:
        return match.group(1) + "_" + match.group(2) + "_" + match.group(3), [int(float(match.group(4).replace(',', '.')) * 1e6), int(match.group(5))]
    assert False, "Parsing error on "+input_string

def parse_UDP(input_string):
    """
        Contains: direction, payload type, iat, payload size
    """
    if "$" in input_string: return "$", [0,0]
    match = re.match(r'([><])/([A-Za-z]+)/(-?\d+.\d+)/(\d+)', input_string)
    if match:
        return match.group(1) + "_" + match.group(2), [int(float(match.group(3).replace(',', '.')) * 1e6), int(match.group(4))]
    assert False, "Parsing error on "+input_string

def parse_ICMP(input_string):
    """
        Contains: direction, iat
    """
    if "$" in input_string: return "$", [0]
    match = re.match(r'([><])/(-?\d+.\d+)', input_string)
    if match:
        return match.group(1), [int(float(match.group(2).replace(',', '.')) * 1e6)]
    assert False, "Parsing error on "+input_string

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Learn timed automata from packet sequences.')
    parser.add_argument('--proto', choices=["TCP","UDP","ICMP"], type=str.upper)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--select_dst_ports', type=int, nargs="+", help="Learn from these specific destination ports. Cannot be used with --ignore_dst_ports.")
    group.add_argument('--ignore_dst_ports', type=int, nargs="+", help="Learn from all ports except these. Cannot be used with --select_dst_ports.")
    parser.add_argument('--input', required=True, help="Select the input file. It must a FosR-netflow file.")
    parser.add_argument('--output', help="Select the output file to create.")
    parser.add_argument('--output_dot', help="Select the dot output file for visualization.")
    parser.add_argument('--verbose', help="Increase TADAM’s verbosity.", action="store_true")
    args = parser.parse_args()
    protocol = args.proto

    select_dst_ports = args.select_dst_ports or []
    ignore_dst_ports = args.ignore_dst_ports or []

    if args.output is None:
        print("No output file specified: using \"automata.json\" by default")
        args.output = "automata.json"

    try:
        df = pd.read_csv(args.input,low_memory=False,names=["protocol","src_ip","dst_ip","dst_port","fwd_packets","bwd_packets","fwd_bytes","bwd_bytes","time_sequence","payloads"])
    except Exception as e:
        print("Input file cannot be opened:",e)
        exit()

    if len(df) == 0:
        print("Input file is empty")
        exit()

    if protocol is None:
        unique = pd.unique(df["protocol"])
        if len(unique) == 1:
            protocol = unique[0].upper()
            if protocol not in ["TCP","UDP","ICMP"]:
                print("Network protocol should be TCP, UDP or ICMP. Found:",str(protocol))
                exit()
        else:
            print("Multiple network protocols detected. Please manually select one with --proto")
            exit()

    df = df[df["protocol"] == protocol]
    if len(select_dst_ports) > 0:
        df = df[df["dst_port"].isin(select_dst_ports)]
    elif len(ignore_dst_ports) > 0:
        df = df[~df["dst_port"].isin(ignore_dst_ports)]
    df = df["time_sequence"]

    len_before = len(df)
    df = df[df.str.len() < 20000]
    if len(df) < len_before:
        print((len_before-len(df)),"flows have been ignored because they are too long.")

    if len(df) == 0:
        print("No stream satisfies these conditions")
        exit()

    print("Learning from",len(df),"examples")

    noise_model = NoiseModel(deletion_possible=False)
    parsers = { "TCP": parse_TCP, "UDP": parse_UDP, "ICMP": parse_ICMP }

    options = Options(filename=None,
                    data_parser=parsers[protocol],
                    guards=GuardsFormat.DISTRIB,
                    search = Search.EXHAUSTIVE,
                    init = Init.STATE_SYMBOL)

    l = exhaustive_search(options, tss_list=df, verbose=args.verbose, noise_model=noise_model)
    # print("Automaton successfully learned")

    d = l.ta.dict_export_ta()
    d["protocol"] = protocol
    metadata = {}
    metadata["select_dst_ports"] = args.select_dst_ports
    metadata["input_file"] = os.path.split(args.input)[-1]
    metadata["ignore_dst_ports"] = args.ignore_dst_ports
    metadata["creation_time"] = str(datetime.datetime.now())
    d["metadata"] = metadata
    try:
        out_file = open(args.output, "w")
        json.dump(d, out_file, indent=4)
        print("JSON file successfully created")
    except Exception as e:
        print("Error during json save:",e)

    if args.output_dot:
        try:
            l.ta.export_ta(args.output_dot, guard_as_distrib=True)
            print("Dot file successfully created")
        except Exception as e:
            print("Error during dot save:",e)

