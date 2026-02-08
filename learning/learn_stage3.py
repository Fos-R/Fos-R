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
import time
import random

pd.options.mode.copy_on_write = True

def add_payload_type(payload_type, row):
    # if row['protocol'] == "ICMP":
    #     return row["time_sequence"] # no payload to analyze

    iat = row['iat'].split(",")
    directions = row["forward_list"].split(",")
    directions = list(map(lambda s: True if s == "T" else False, directions))
    payloads = row["payloads"].split(",")
    payloads = list(map(lambda s: "" if s == "(empty)" else base64.standard_b64decode(s).hex(), payloads))

    if 'flags' in row: # TCP only
        headers = row['flags'].split(",")
        headers = list(map(lambda s: s+"/", headers))
    else:
        headers = [""]*len(payloads)

    nb_replay = 0
    nb_random = 0
    nb_text = 0
    for i,p in enumerate(payloads):
        if directions[i]:
            headers[i]+=">"
        else:
            headers[i]+="<"
        headers[i]+="/"+iat[i]
        headers[i]+="/"+str(int(len(p)/2)) # 2 hex digits per byte

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
                    s = s.translate({10: " ", 13: " "}) # replace CR and LF by whitespace
                    if s.isprintable() or payload_type == "text":
                        if len(s.split()[0]) <= 10: # check if we detect a keyword at the beginning
                            headers[i]+="/Text:"+s.split()[0].replace("$","-") # To avoid detecting the end-of-sequence symbol
                        else:
                            headers[i]+="/Text"
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
    """
        Contains: flags, direction, iat, payload size, payload type
    """
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

    def __init__(self, verbose, metadata, output_name, protocol, payloads):
        self.metadata = metadata
        self.verbose = verbose
        self.output_name = output_name
        self.protocol = protocol
        self.payloads = payloads

    def export_automata(self, ta):
        tmp = []
        for e in ta.edges:
            d = {}
            if "Text" in e.symbol:
                tss = []
                for ts, t in e.tss.items():
                    tss = tss + [self.payloads[ts][a] for (a,_) in t]
                values, counts = np.unique(tss, return_counts=True)
                content = []
                for i,s in enumerate(values):
                    try:
                        # Due to a TADAM bug, it can fail
                        content.append(base64.standard_b64decode(s).decode('utf-8'))
                    except Exception as e:
                        print("UTF-8 decoding error: skipping", e)
                        content.append("")
                        counts[i] = 0
                d["payloads"] = { "type": "Text", "content": content }
                # save the weights only if it’s not equiprobable
                if any(c != counts[0] for c in counts):
                    d["payloads"]["weights"] = [int(i) for i in counts]
            elif "Replay" in e.symbol:
                tss = []
                for ts, t in e.tss.items():
                    tss = tss + [self.payloads[ts][a] for (a,_) in t]
                values, counts = np.unique(tss, return_counts=True)
                d["payloads"] = { "type": "Base64", "content": [str(s) for s in values] }
                # save the weights only if it’s not equiprobable
                if any(c != counts[0] for c in counts):
                    d["payloads"]["weights"] = [int(i) for i in counts]
            elif "Random" in e.symbol:
                lengths = []
                for ts, t in e.tss.items():
                    lengths = lengths + [len(base64.standard_b64decode(self.payloads[ts][a])) for (a,_) in t]
                values, counts = np.unique(lengths, return_counts=True)
                d["payloads"] = { "type": "Lengths", "lengths": [int(v) for v in values] }
                # save the weights only if it’s not equiprobable
                if any(c != counts[0] for c in counts):
                    d["payloads"]["weights"] = [int(i) for i in counts]
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
            json.dump(d, out_file2, indent=1)
            if self.verbose:
                print("JSON file successfully created:", self.output_name)
        except Exception as e:
            print("Error during json save:", e)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Learn timed automata from packet sequences.')
    parser.add_argument('--flows', required=True, type=str.lower, help="The flow list generated by learn_stage2.py.")
    parser.add_argument('--service', type=str.lower, help="Learn from this specific service.")
    # parser.add_argument('--dst-port', type=int, help="Restrict to this destination port.")
    parser.add_argument('--input', required=True, help="Select the input directory.")
    # parser.add_argument('--automaton-name', help="The name of the automaton.")
    parser.add_argument('--conn-state', choices=["SF", "SH", "RST", "S0", "REJ"], help="Learn for one connection state only. TCP only.")
    # parser.add_argument('--payload-type', choices=["encrypted", "text", "binary"], help="Select a payload type.", type=str.lower)
    parser.add_argument('--subsample', type=int, help="How many flows to learn from at most.")
    parser.add_argument('--output', help="Select the output directory (by default the local directory)")
    # parser.add_argument('--output-dot', help="Select the dot output file for visualization.")
    parser.add_argument('--force', help="Learn even if the output file already exists.", action="store_true")
    parser.add_argument('--verbose', help="Increase TADAM’s verbosity.", action="store_true")
    args = parser.parse_args()
    args.output = args.output or "."

    os.environ["OMP_NUM_THREADS"] = "1"

    # if args.automaton_name:
    #     if args.output is None:
    #         args.output = args.automaton_name+".json"
    #     if args.output_dot is None:
    #         args.output_dot = args.automaton_name+".dot"
    # else:
    #     args.automaton_name = args.service or "all-services"

    #     service = args.service or "all"
    #     if args.output is None:
    #         args.output = service+".json"
    #     if args.output_dot is None:
    #         args.output_dot = service+".dot"

    # output_name = args.output

    try:
        print("Loading files")
        csv.field_size_limit(sys.maxsize) # payload is too long
        conn_input = os.path.join(args.input, "conn.log")
        flow = pd.read_csv(conn_input, header = 8, engine = "python", skipfooter = 1, sep = "\t", names = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp", "missed_bytes", "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "tunnel_parents", "ip_proto"])

        file_input = os.path.join(args.input, "fosr_tcp.log")
        df = pd.read_csv(file_input, header = 8, engine = "python", skipfooter = 1, sep = "\t", names = ["ts", "uid", "payloads", "iat", "forward_list", "service", "flags", "conn_state"])
        # print("Services in the TCP file:\n",df["service"].value_counts())
        df = df.join(flow.set_index("uid"), on="uid", rsuffix="_conn")
        prev_len = len(df)
        df = df[df["iat"].map(len) < 1000] # remove incomplete flows (1000 is defined in fosr.zeek)
        if prev_len > len(df):
            print((prev_len-len(df)),"TCP flows have been ignored because they are too long.")
        df_tcp = df

        file_input = os.path.join(args.input, "fosr_udp.log")
        df = pd.read_csv(file_input, header = 8, engine = "python", skipfooter = 1, sep = "\t", names = ["ts", "uid", "payloads", "iat", "forward_list", "service"])
        # print("Services in the UDP file:\n",df[["service"]].value_counts())
        df = df.join(flow.set_index("uid"), on="uid", rsuffix="_conn")
        prev_len = len(df)
        df = df[df["iat"].map(len) < 1000] # remove incomplete flows (1000 is defined in fosr.zeek)
        if prev_len > len(df):
            print((prev_len-len(df)),"UDP flows have been ignored because they are too long.")
        df_udp = df

        with open(args.flows) as f:
            flows = json.load(f)

    except Exception as e:
        print("Input file cannot be opened:",e)
        exit(1)

    for d in flows:
        random.seed(0)
        protocol = d["proto"]
        conn_state = d.get("conn_state")
        service = d["service"]

        # skip unwanted services and conn_state
        if args.service is not None and args.service != d["service"]:
            continue
        if args.conn_state is not None and args.conn_state != conn_state:
            continue

        if conn_state is None:
            output_name = os.path.join(args.output, service+".json")
        else:
            output_name = os.path.join(args.output, service+"-"+conn_state+".json")

        if os.path.isfile(output_name) and not args.force:
            print(f"File {output_name} already exists: skipping")
            continue

        if d.get("conn_state") is None:
            print("Learning for service",d["service"])
        else:
            print("Learning for service",d["service"],"with connection state",d["conn_state"])

        if protocol == "tcp":
            df = df_tcp[df_tcp["uid"].isin(d["flows"])]

        elif protocol == "udp":
            df = df_udp[df_udp["uid"].isin(d["flows"])]

        if len(df) == 0:
            print("Input file is empty, skipping")
            continue

        all_df = df

        assert len(df) > 0 # by construction

        if args.subsample and len(df) > args.subsample:
            df = df.sample(n=args.subsample, random_state=0)

        df["time_sequence"] = df.apply(partial(add_payload_type,None), axis=1)
        df = df.reset_index(drop=True)

        print("Learning from",len(df),"examples")

        noise_model = NoiseModel(deletion_possible=False, addition_possible=False, reemission_possible=False, transposition_possible=True)
        parsers = { "tcp": parse_TCP, "udp": parse_UDP, "icmp": parse_ICMP }

        options = Options(filename=None,
                        data_parser=parsers[protocol],
                        guards=GuardsFormat.DISTRIB,
                        search = Search.EXHAUSTIVE,
                        init = Init.STATE_SYMBOL)

        metadata = {}
        metadata["service"] = service
        metadata["conn_state"] = conn_state or "none"
        # metadata["dst_port"] = args.dst_port or "none"
        metadata["input_file"] = os.path.split(args.input)[-1]
        metadata["creation_time"] = str(datetime.datetime.now())
        # metadata["automaton_name"] = args.automaton_name

        payloads = df["payloads"].apply(lambda l:list(map(lambda s: "" if s == "(empty)" else s, l.split(","))))

        exporter = Exporter(args.verbose, metadata, output_name, protocol, payloads)
        start = time.time()
        try:
            l = exhaustive_search(options, tss_list=df["time_sequence"], verbose=args.verbose, noise_model=noise_model, on_iter=exporter.export_automata)
        except Exception as e:
            print("Fatal error during TADAM learning: skipping",e)
        print("Learning time:", time.time() - start)

        ta = l.ta
        print("Automaton successfully learned")

        try:
            if conn_state is None:
                output_name_dot = os.path.join(args.output, service+".dot")
            else:
                output_name_dot = os.path.join(args.output, service+"-"+conn_state+".dot")

            l.ta.export_ta(output_name_dot, guard_as_distrib=True)
            print("Dot file successfully created:",output_name_dot)
        except Exception as e:
            print("Error during dot save:",e)



