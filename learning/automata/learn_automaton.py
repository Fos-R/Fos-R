import os
import argparse
import re
import json
import base64
from functools import partial
from tadam.tadam import exhaustive_search, opportunistic_search
from tadam.mdl import NoiseModel
from tadam.options import Options, GuardsFormat, Init, Search
import pandas as pd
import datetime
from scipy.stats import chisquare
import numpy as np
import sys
import csv

def add_payload_type(payload_type, row):
    # if row['protocol'] == "ICMP":
    #     return row["time_sequence"] # no payload to analyze

    headers = row['flags'].split(",")
    iat = row['iat'].split(",")
    directions = row["forward_list"].split(",")
    directions = list(map(lambda s: True if s == "T" else False, directions))
    payloads = row["payloads"].split(",")
    payloads = list(map(lambda s: "" if s == "(empty)" else base64.standard_b64decode(s).hex(), payloads))

    nb_replay = 0
    nb_random = 0
    nb_text = 0
    for i,p in enumerate(payloads):
        if directions[i]:
            headers[i]+="/>"
        else:
            headers[i]+="/<"
        headers[i]+="/"+iat[i]
        headers[i]+="/"+str(int(len(p)/2)) # 2 hex digits per byte

        # TODO: utiliser des nibbles (et pas half)-nibbles si on a assez d’exemples ?
        hnibbles = [int(v,16)%4 for v in list(p)]+[int(v,16)//4 for v in list(p)]
        if len(hnibbles)==0: # only P:, i.e., empty payload
            headers[i]+="/Empty"
        else:
            random = False
            if len(hnibbles) >= 20: # expected number of observations should be at least 5. There are 4 categories, so that’s at least 20 examples. Since each byte is split into 4 half-nibbles, it means that we need at least 5 bytes.
                obs = [0]*4
                for j in range(4):
                    obs[j] += hnibbles.count(j)
                random = (chisquare(obs).pvalue >= 0.05)
            if random or payload_type == "encrypted":
                headers[i]+="/Random"
                nb_random += 1
                # print("Detected as random")
            else:
                replay = True
                try:
                    s = bytes.fromhex(p).decode('utf-8')
                    s = s.translate({10: "", 13: ""}) # remove CR and LF
                    if s.isprintable() or payload_type == "text":
                        headers[i]+="/Text:"+s.split()[0][:10].replace("$","")
                        # print(s, s.split()[0])
                        replay = False
                        # print("Detected as text")
                        nb_text += 1
                except: # cannot decode: not text
                    pass
                if replay:
                    headers[i]+="/Replay"
                    # print("Detected as replay")
                    nb_replay += 1
    # print("Type inference. Replay:",nb_replay,"Random:",nb_random,"Text:",nb_text)
    return " ".join(headers)

def parse_TCP(input_string):
    if "$" in input_string: return "$", [0,0]
    regex_format2 = r'([A-Za-z]+)/([><])/(-?\d+\.?\d*)/(\d+)/(.+)'
    match = re.match(regex_format2, input_string)
    if match:
        return match.group(1) + "_" + match.group(2) + "_" + match.group(5), [int(float(match.group(3).replace(',', '.')) * 1e3), int(match.group(4))]
    else:
        assert False, "Parsing error on "+input_string

def parse_UDP(input_string):
    """
        Contains: direction, iat, payload size, payload type
    """
    if "$" in input_string: return "$", [0,0]
    match = re.match(r'([><])/(-?\d+\.?\d*)/(\d+)/(.+)', input_string)
    if match:
        return match.group(1) + "_" + match.group(4), [int(float(match.group(2).replace(',', '.')) * 1e6), int(match.group(3))]
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

class Exporter:

    def __init__(self, metadata, output_name, protocol, payloads):
        self.metadata = metadata
        self.output_name = output_name
        self.protocol = protocol
        self.payloads = payloads

    def export_automata(self, ta):
        tmp = []
        for e in ta.edges:
            d = {}
            if "Replay" in e.symbol:
                tss = []
                for ts, t in e.tss.items():
                    tss = tss + [self.payloads[ts][a] for (a,_) in t]
                values, counts = np.unique(tss, return_counts=True)
                d["payloads"] = { "content": [str(s) for s in tss] }
                # save the weights only if it’s not equiprobable
                if any(c != counts[0] for c in counts):
                    d["payloads"]["weights"] = [int(i) for i in counts]
                d["payloads"]["type"] = "Base64"
            elif "Text" in e.symbol:
                tss = []
                for ts, t in e.tss.items():
                    tss = tss + [self.payloads[ts][a] for (a,_) in t]
                values, counts = np.unique(tss, return_counts=True)
                d["payloads"] = { "content": [base64.standard_b64decode(s).decode('utf-8') for s in values] }
                # save the weights only if it’s not equiprobable
                if any(c != counts[0] for c in counts):
                    d["payloads"]["weights"] = [int(i) for i in counts]
                d["payloads"]["type"] = "Text"
            elif "Random" in e.symbol:
                lengths = []
                for ts, t in e.tss.items():
                    lengths = lengths + [len(base64.standard_b64decode(self.payloads[ts][a])) for (a,_) in t]
                d["payloads"] = { "type": "Lengths", "lengths": lengths }
            else:
                d["payloads"] = { "type": "NoPayload" }
            # if empty: keep tss empty
            d["p"] = e.proba
            d["count"] = len(e.tss)
            d["src"] = ta.states.index(e.source)
            d["dst"] = ta.states.index(e.destination)
            d["symbol"] = e.symbol
            d["mu"] = e.mu.tolist()
            d["cov"] = e.cov.tolist()
            tmp.append(d)

        noise = {}
        noise["none"] = 2**(-ta.cost_transition)
        noise["deletion"] = 2**(-ta.cost_deletion)
        noise["reemission"] = 2**(-ta.cost_reemission)
        noise["transposition"] = 2**(-ta.cost_transposition)
        noise["addition"] = 2**(-ta.cost_addition)
        s = sum(noise.values())
        for k,v in noise.items(): # normalize, just in case
            noise[k] = v/s

        d = { "edges": tmp, "noise": noise }
        for i,n in enumerate(ta.states):
            if n.initial:
                d["initial_state"] = i
            if n.accepting:
                d["accepting_state"] = i

        d["protocol"] = self.protocol
        d["metadata"] = self.metadata
        try:
            out_file2 = open(self.output_name, "w")
            json.dump(d, out_file2, indent=4)
            # out_file = open(output_name.rsplit(".",1)[0]+"_human_readable.json", "w")
            # json.dump(d, out_file, indent=4)
            print("JSON file successfully created:", self.output_name)
        except Exception as e:
            print("Error during json save:", e)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Learn timed automata from packet sequences.')
    parser.add_argument('--proto', required=True, choices=["TCP","UDP"], type=str.upper)
    parser.add_argument('--service', required=True, type=str.lower, help="Learn from this specific service.")
    parser.add_argument('--dst-port', type=int, help="Restrict to this destination port.")
    parser.add_argument('--input', required=True, help="Select the input directory.")
    parser.add_argument('--automaton-name', help="The name of the automaton.")
    parser.add_argument('--conn-state', choices=["SF", "SH", "RST", "S0", "REJ"], help="Learn for one connection state only. TCP only.")
    parser.add_argument('--payload-type', choices=["encrypted", "text", "binary"], help="Select a payload type.", type=str.lower)
    parser.add_argument('--subsample', type=int, help="How many flows to learn from at most.")
    parser.add_argument('--output', help="Select the output file to create.")
    parser.add_argument('--output-dot', help="Select the dot output file for visualization.")
    parser.add_argument('--verbose', help="Increase TADAM’s verbosity.", action="store_true")
    args = parser.parse_args()
    protocol = args.proto

    os.environ["OMP_NUM_THREADS"] = "1"

    if args.automaton_name:
        if args.output is None:
            args.output = args.automaton_name+".json"
        if args.output_dot is None:
            args.output_dot = args.automaton_name+".dot"
    else:
        if args.output is None:
            args.output = args.service+".json"
        if args.output_dot is None:
            args.output_dot = args.service+".dot"

    output_name = args.output

    try:
        print("Loading file")
        csv.field_size_limit(sys.maxsize) # payload is too long
        if protocol == "TCP":
            file_input = os.path.join(args.input, "fosr_tcp.log")
            df = pd.read_csv(file_input, header = 8, engine = "python", skipfooter = 1, sep = "\t", names = ["ts", "uid", "payloads", "iat", "forward_list", "service", "dst_port", "flags", "conn_state"])
            print("Services in this file:",df["service"].unique())
            if args.dst_port:
                df = df[df["dst_port"] == args.dst_port]
            df = df[df["service"] == args.service]
            df = df[(df["conn_state"]!="other")]
            conn_states = df["conn_state"].unique()
            if args.conn_state:
                print(f"Learning for connection state {args.conn_state} only")
                assert args.conn_state in conn_states
                conn_states = [args.conn_state]

        elif protocol == "UDP":
            file_input = os.path.join(args.input, "fosr_udp.log")
            df = pd.read_csv(file_input, header = 8, engine = "python", skipfooter = 1, sep = "\t", names = ["ts", "uid", "payloads", "iat", "forward_list", "service", "dst_port"])
            conn_states = [None]

    except Exception as e:
        print("Input file cannot be opened:",e)
        exit(1)

    if len(df) == 0:
        print("Input file is empty")
        exit()

    all_df = df

    for state in conn_states:
        if state is None: # not TCP: use everything
            df = all_df
        else:
            print(f"Learning for connection state {state}")
            df = all_df[all_df["conn_state"] == state]
            output_name = state+"-"+args.output

        assert len(df) > 0 # by construction

        if args.subsample and len(df) > 2*args.subsample:
            df = df.sample(n=2*args.subsample)

        df["time_sequence"] = df.apply(partial(add_payload_type,args.payload_type), axis=1)

        len_before = len(df)
        df = df[df["time_sequence"].str.len() < 20000]
        if len(df) < len_before:
            print((len_before-len(df)),"flows have been ignored because they are too long.")

        if args.subsample and len(df) > args.subsample:
            df = df.sample(n=args.subsample)
            print("Subsampling to",args.subsample,"examples")

        df = df.reset_index(drop=True)

        # print("Learning from",len(df),"examples")

        noise_model = NoiseModel(deletion_possible=False, addition_possible=False, reemission_possible=False)
        parsers = { "TCP": parse_TCP, "UDP": parse_UDP, "ICMP": parse_ICMP }

        options = Options(filename=None,
                        data_parser=parsers[protocol],
                        guards=GuardsFormat.DISTRIB,
                        search = Search.EXHAUSTIVE,
                        init = Init.STATE_SYMBOL)

        metadata = {}
        metadata["service"] = args.service
        metadata["conn_state"] = state
        metadata["dst_port"] = args.dst_port or "none"
        metadata["input_file"] = os.path.split(args.input)[-1]
        metadata["creation_time"] = str(datetime.datetime.now())
        metadata["automaton_name"] = args.automaton_name or "unnamed"

        payloads = df["payloads"].apply(lambda l:list(map(lambda s: "" if s == "(empty)" else s, l.split(","))))

        exporter = Exporter(metadata, output_name, protocol, payloads)
        l = exhaustive_search(options, tss_list=df["time_sequence"], verbose=args.verbose, noise_model=noise_model, on_iter=exporter.export_automata)
        ta = l.ta
        print("Automaton successfully learned")

        if args.output_dot:
            try:
                l.ta.export_ta(args.output_dot, guard_as_distrib=True)
                print("Dot file successfully created:",args.output_dot)
            except Exception as e:
                print("Error during dot save:",e)

