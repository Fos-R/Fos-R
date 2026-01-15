# Data to generate: src_ip, dst_ip, src_port, dst_port, ttl_client, ttl_server, fwd_pckets_count, bwd_packets_count, proto

import argparse
import numpy as np
import pandas as pd
import random
from sklearn.mixture import GaussianMixture
import json
import pyagrum as gum
import os
import sys
import csv
import functools

def group_ip_dst(value):
    value = str(value)
    local_net = ['192.168.', '10.', '0.', '127.', '172.', '192.0.0', '198.18', '198.19']
    for ip in local_net:
        if value.startswith(ip):
            return 'Local'
    return 'Internet'

def remove_public_ip(value):
    if group_ip_dst(value) == "Internet":
        return "Internet"
    return value

def get_network_role(ip, clients, servers):
    if ip in clients:
        return "User"
    elif ip in servers:
        return "Server"
    else:
        return "Internet"

def to_string(n):
    return "port-"+str(int(n))

bin_count = 24*4

def categorize_time(t):
    n = int(t % (60*60*24) // (60*60*24 / bin_count))
    return "bin-"+f'{n:03}'

# Adapted from https://pyagrum.readthedocs.io/en/1.13.0/notebooks/17-Examples_parametersLearningWithPandas.html#A-global-method-for-estimating-Bayesian-network-parameters-from-CSV-file-using-PANDAS
def computeCPTfromDF(bn,df,name):
    """
    Compute the CPT of variable "name" in the BN bn from the database df
    """
    id=bn.idFromName(name)
    parents=list(reversed(bn.cpt(id).names))
    domains=[bn[name].domainSize()
             for name in parents]
    parents.pop()

    if (len(parents)>0):
        c=pd.crosstab(df[name],[df[parent] for parent in parents], dropna=False)
        s=c/c.sum().apply(np.float32)
    else:
        s=df[name].value_counts(normalize=True)

    s.fillna(0, inplace=True)
    bn.cpt(id)[:]=np.array((s).transpose()).reshape(*domains)

def ParametersLearning(bn,df):
    """
    Compute the CPTs of every varaible in the BN bn from the database df
    Use no prior and replace NaN with 0.
    """
    for name in bn.names():
        computeCPTfromDF(bn,df,name)

def complete_proto(l, port):
    if ":" in port: # already a service
        return port.split(":")[0]
    for service in l:
        if service.endswith(":"+port):
            return service.split(":")[0]
    return pd.NA

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Learn a time profile for Fos-R.')
    parser.add_argument('--input', required=True, help="Select the input folder.")
    parser.add_argument('--output', help="Select the output directory.")
    args = parser.parse_args()

    conn_input = os.path.join(args.input, "conn.log")

    tcp_input = os.path.join(args.input, "fosr_tcp.log")
    udp_input = os.path.join(args.input, "fosr_udp.log")

    ttl_input = os.path.join(args.input, "fosr_ttl.log")

    random.seed(0)
    gum.initRandom(seed=42)

    output = {}
    output["s0_bin_count"] = bin_count

    print("Loading files")

    csv.field_size_limit(sys.maxsize) # payload is too long
    try:
        flow = pd.read_csv(conn_input, header = 8, engine = "python", skipfooter = 1, sep = "\t", names = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp", "missed_bytes", "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "tunnel_parents", "ip_proto"])
    except Exception as e:
        print(f"Cannot find conn.log in {args.input}!",e)
        exit(1)

    tcp_fosr = None
    try:
        tcp_fosr = pd.read_csv(tcp_input, header = 8, engine = "python", skipfooter = 1, sep = "\t", names = ["ts", "uid", "payloads", "iat", "forward_list", "service", "flags", "conn_state"])
    except Exception as e:
        print("No TCP data:",e)
    udp_fosr = None
    try:
        udp_fosr = pd.read_csv(udp_input, header = 8, engine = "python", skipfooter = 1, sep = "\t", names = ["ts", "uid", "payloads", "iat", "forward_list", "service"])
    except Exception as e:
        print("No UDP data", e)
    ttl_fosr = pd.read_csv(ttl_input, header = 8, engine = "python", skipfooter = 1, sep = "\t", names = ["uid", "ip", "ttl", "proto"]);

    print("Services in the TCP file:\n",tcp_fosr["service"].value_counts())
    print("Services in the UDP file:\n",udp_fosr["service"].value_counts())

    print("Extracting")
    flow["Time"] = flow["ts"].apply(categorize_time)

    flow["Proto"] = flow["proto"].str.upper()

    # Remove non-UDP and non-TCP flows
    flow = flow[(flow["Proto"]=="TCP") | (flow["Proto"]=="UDP")]

    if tcp_fosr is not None:
        flow = flow.join(tcp_fosr.set_index("uid"), on="uid", rsuffix="_tcp_fosr")
        flow['Connection State'] = flow['conn_state_tcp_fosr']
        flow = flow[(flow["Connection State"]!="other")] # remove rare and OTH connection states
        flow["service_tcp_fosr"] = flow["service_tcp_fosr"].fillna("")

    if udp_fosr is not None:
        flow = flow.join(udp_fosr.set_index("uid"), on="uid", rsuffix="_udp_fosr")
        flow["service_udp_fosr"] = flow["service_udp_fosr"].fillna("")

    # one or the other will be empty
    flow['Applicative Proto'] = flow['service_tcp_fosr'] + flow['service_udp_fosr']

    # remove flows with unknown service
    flow = flow[flow["Applicative Proto"] != ""]

    # get all the services detected
    services = [s for s in flow['Applicative Proto'].unique() if ":" in s]
    print("Recognized services:",services)
    # some flow’s protocols may not be corrected infered (S0’s for example). We use the other flows to infer the service
    flow["Applicative Proto"] = flow["Applicative Proto"].apply(functools.partial(complete_proto,services))
    # we remove flows with unknown service
    flow = flow.dropna(subset="Applicative Proto")

    m = 0.001 * len(flow) # remove services that appear less than 0.1% of the time
    print("Removed rare services:\n",flow["Applicative Proto"].value_counts()[flow["Applicative Proto"].value_counts() <= m])
    flow = flow[flow["Applicative Proto"].isin(flow["Applicative Proto"].value_counts()[flow["Applicative Proto"].value_counts() > m].index)]

    # Export for automata learning

    print("Export for automata learning")
    automata = []
    for s in flow["Applicative Proto"].unique():
        if not flow[flow["Applicative Proto"] == s].isnull().all(axis=0)["Connection State"]: # TCP
            for conn_state in flow[flow["Applicative Proto"] == s]["Connection State"].unique():
                if str(conn_state) != "NaN":
                    flows = list(flow[(flow["Applicative Proto"] == s) & (flow["Connection State"] == conn_state)]["uid"])
                    if len(flows) > 0:
                        d = { "service": s, "conn_state": conn_state, "flows": flows, "proto": "tcp" }
                        automata.append(d)
        else: # not TCP
            flows = list(flow[flow["Applicative Proto"] == s]["uid"])
            if len(flows) > 0:
                d = { "service": s, "flows": flows, "proto": "udp" }
                automata.append(d)

    out_file = open(os.path.join(args.output, "automata-flows.json"), "w")
    json.dump(automata, out_file, indent=1)

    # anonymise public IP
    flow['Src IP Addr'] = flow['id.orig_h'].apply(remove_public_ip)
    flow['Dst IP Addr'] = flow['id.resp_h'].apply(remove_public_ip)
    flow['Dst Pt'] = flow['id.resp_p'].apply(to_string)

    # get all the local IP addresses
    ips = list(set(flow["Src IP Addr"].tolist()).union(set(flow["Dst IP Addr"].tolist())))
    ips.sort()
    ips = [ip for ip in ips if group_ip_dst(ip) == "Local"]

    clients = []
    servers = []

    ttl = {}

    for ip in ips:
        occurrences_dst = sum(flow["Dst IP Addr"]==ip)
        occurrences_src = sum(flow["Src IP Addr"]==ip)
        if occurrences_src >= occurrences_dst:
            # print(ip,"is a client")
            clients.append(ip)
        else:
            # print(ip,"is a server")
            servers.append(ip)

        # broadcast IP will be have no TTL
        if ip in ttl_fosr["ip"].values:
            # use the most common TTL
            ttl[ip] = int(ttl_fosr[ttl_fosr["ip"] == ip]["ttl"].mode()[0])

    output["ttl"] = ttl
    print("Local clients:",list(clients))
    print("Local servers:",list(servers))

# only for local addresses
    flow['Src IP Role'] = flow['Src IP Addr'].apply(get_network_role, clients=clients, servers=servers)
    flow['Dst IP Role'] = flow['Dst IP Addr'].apply(get_network_role, clients=clients, servers=servers)

    if tcp_fosr is not None:
        TCP_out_pkt_count = np.array(flow[flow['Proto']=="TCP"]["orig_pkts"]).reshape(-1,1)
        TCP_in_pkt_count = np.array(flow[flow['Proto']=="TCP"]["resp_pkts"]).reshape(-1,1)
    if udp_fosr is not None:
        UDP_out_pkt_count = np.array(flow[flow['Proto']=="UDP"]["orig_pkts"]).reshape(-1,1)
        UDP_in_pkt_count = np.array(flow[flow['Proto']=="UDP"]["resp_pkts"]).reshape(-1,1)

    def categorize(pkt_count):
        best_bic = None
        for i in range(5): # limit on the number of components
            if i+1 > len(pkt_count): # at most as many components as the number of points
                break
            try:
                m = GaussianMixture(n_components=i+1, random_state=42, covariance_type="spherical")
                labels = m.fit_predict(pkt_count)
                bic = m.bic(pkt_count)
                if best_bic is None or best_bic > bic:
                    best_model = m
                    best_bic = bic
                    best_labels = labels
            except Exception as e:
                print("Error during GaussianMixture:",e)
        assert best_bic is not None
        best_labels = list(map(str,best_labels)) # make the variable discrete
        return best_model.means_.reshape(1,-1)[0], best_model.covariances_, best_labels

    if tcp_fosr is not None:
        print("Gaussian mixture for TCP out packet count")
        mu, cov, labels = categorize(TCP_out_pkt_count)
        output["tcp_out_pkt_gaussians"] = {"mu": mu.tolist(), "cov": cov.tolist()}
        flow.loc[flow['Proto']=="TCP", ["Cat Out Packet"]] = labels

        print("Gaussian mixture for TCP in packet count")
        mu, cov, labels = categorize(TCP_in_pkt_count)
        output["tcp_in_pkt_gaussians"] = {"mu": mu.tolist(), "cov": cov.tolist()}
        flow.loc[flow['Proto']=="TCP", ["Cat In Packet"]] = labels

    if udp_fosr is not None:
        print("Gaussian mixture for UDP out packet count")
        mu, cov, labels = categorize(UDP_out_pkt_count)
        output["udp_out_pkt_gaussians"] = {"mu": mu.tolist(), "cov": cov.tolist()}
        flow.loc[flow['Proto']=="UDP", ["Cat Out Packet"]] = labels

        print("Gaussian mixture for UDP in packet count")
        mu, cov, labels = categorize(UDP_in_pkt_count)
        output["udp_in_pkt_gaussians"] = {"mu": mu.tolist(), "cov": cov.tolist()}
        flow.loc[flow['Proto']=="UDP", ["Cat In Packet"]] = labels

    flow = flow.replace("-", "none") # "-" causes pyagrum to parse the value as a number, leading to an exception

    # Common variables:
        # Time
        # Src IP Role
        # Dst IP Role
        # Applicative Protocol
    common_vars = ["Time", "Src IP Role", "Dst IP Role", "Applicative Proto", "Proto", "Src IP Addr", "Dst IP Addr", "Dst Pt"]
    common_data = flow[common_vars]

    vars_without_children = ["Src IP Addr", "Dst IP Addr", "Dst Pt"]

    # TCP-only variables:
        # In Pkt Count
        # Out Pkt Count
        # Connection State

    tcp_vars = ["Cat Out Packet", "Cat In Packet", "Connection State"]
    tcp_data = flow[flow['Proto']=="TCP"]
    tcp_data = tcp_data[tcp_vars + common_vars]
    tcp_data = tcp_data.dropna()

    # UDP-only variables:
        # In Pkt Count
        # Out Pkt Count

    udp_vars = ["Cat Out Packet", "Cat In Packet"]
    udp_data = flow[flow['Proto']=="UDP"]
    udp_data = udp_data[udp_vars + common_vars]

    # Variables not used during structure learning (saved as dictionaries alongside the BN)
        # Dst Port
        # Src IP Addr
        # Dst IP Addr

    print("Model learning")

    learner_common = gum.BNLearner(common_data)
    # Time must have no parent because it will be sampled from the stage 0
    learner_common.addNoParentNode("Time") # variable with no parent
    # Src IP Addr and Dst IP Addr must have no children because we want to modify their CPT with the configuration file
    for var in vars_without_children:
        learner_common.addNoChildrenNode(var) # variable with no children

    learner_common.useMIIC()
    bn_common = learner_common.learnBN()
    ParametersLearning(bn_common, common_data)

    if udp_fosr is not None:
        learner_udp = gum.BNLearner(udp_data)
        for var in common_vars:
            learner_udp.addNoParentNode(var) # variable with no parent
        for var in vars_without_children:
            learner_udp.addNoChildrenNode(var) # variable with no children

        learner_udp.useMIIC()
        bn_udp = learner_udp.learnBN()
        ParametersLearning(bn_udp, udp_data)

    if tcp_fosr is not None:
        learner_tcp = gum.BNLearner(tcp_data)
        for var in common_vars:
            learner_tcp.addNoParentNode(var) # variable with no parent
        for var in vars_without_children:
            learner_tcp.addNoChildrenNode(var) # variable with no children

        learner_tcp.useMIIC()
        bn_tcp = learner_tcp.learnBN()
        ParametersLearning(bn_tcp, tcp_data)

    print("Model export")

    args.output = args.output or "."
    if not os.path.exists(args.output):
        os.makedirs(args.output)
    bn_common.saveBIFXML(os.path.join(args.output, "bn_common.bifxml"))
    if udp_fosr is not None:
        bn_udp.saveBIFXML(os.path.join(args.output, "bn_udp.bifxml"))
    if tcp_fosr is not None:
        bn_tcp.saveBIFXML(os.path.join(args.output, "bn_tcp.bifxml"))

    try:
        out_file = open(os.path.join(args.output, "bn_additional_data.json"), "w")
        json.dump(output, out_file, indent=1)
        print("JSON file successfully created")
    except Exception as e:
        print("Error during json save:",e)

