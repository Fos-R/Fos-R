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
import pyagrum.lib.image as gumimage
from IPython.display import Image
import time

pd.options.mode.copy_on_write = True

def reorder_services(value):
    l = value.split(",")
    l.sort()
    return ",".join(l)

def remove_public_ip(value, local_ips):
    if value in local_ips:
        return value
    else:
        return "Internet"

def get_network_role(ip, clients, servers):
    if ip in clients:
        return "User"
    elif ip in servers:
        return "Server"
    else:
        return "Internet"

def ttl_to_string(n):
    if n == "":
        return ""
    n = int(n)
    return "ttl-"+f'{n:03}'

def port_to_string(n, rare_ports):
    if n in rare_ports:
        return "unique"
    return "port-"+f'{n:05}'

def cluster_to_string(n):
    # to ensure alphabetical order = numerical order
    return "cluster-"+f'{n:03}'

bin_count = 24

def categorize_time(offset, t):
    n = int((t + 60 * 60 * offset) % (60*60*24) // (60*60*24 / bin_count))
    # to ensure alphabetical order = numerical order
    return "bin-"+f'{n:03}'

full_domains = {}

# Adapted from https://pyagrum.readthedocs.io/en/1.13.0/notebooks/17-Examples_parametersLearningWithPandas.html#A-global-method-for-estimating-Bayesian-network-parameters-from-CSV-file-using-PANDAS
def computeCPTfromDF(bn,df,name):
    """
    Compute the CPT of variable "name" in the BN bn from the database df
    """
    id=bn.idFromName(name)
    parents=list(reversed(bn.cpt(id).names))
    domains = [len(full_domains[name]) for name in parents]

    parents.pop()

    if (len(parents)>0):
        c=pd.crosstab(df[name],[df[parent] for parent in parents], dropna=False)
        s=c/c.sum().apply(np.float32)
    else:
        s=df[name].value_counts(normalize=True, sort=False)

    s.fillna(0, inplace=True)
    bn.cpt(id)[:]=np.array((s).transpose()).reshape(*domains)

def parameters_learning(bn,df):
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
    parser = argparse.ArgumentParser(description='Learn a Bayesian network for Fos-R.')
    parser.add_argument('--input', required=True, help="Select the input folder.")
    parser.add_argument('--output', help="Select the output directory.")
    parser.add_argument('--offset', help="Offset from UTC (in hours).", type=float)
    args = parser.parse_args()
    args.offset = args.offset or 0 # default: consider it’s UTC

    conn_input = os.path.join(args.input, "conn.log")

    tcp_input = os.path.join(args.input, "fosr_tcp.log")
    udp_input = os.path.join(args.input, "fosr_udp.log")

    random.seed(0)
    gum.initRandom(seed=42)

    print("Loading files")

    csv.field_size_limit(sys.maxsize) # payload is too long
    try:
        flow = pd.read_csv(conn_input, header = 8, engine = "python", skipfooter = 1, sep = "\t", names = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp", "missed_bytes", "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "tunnel_parents", "ip_proto"])
    except Exception as e:
        print(f"Cannot find conn.log in {args.input}!",e)
        exit(1)

    tcp_fosr = None
    try:
        tcp_fosr = pd.read_csv(tcp_input, header = 8, engine = "python", skipfooter = 1, sep = "\t", names = ["ts", "uid", "payloads", "iat", "forward_list", "orig_l2_addr", "resp_l2_addr", "orig_ttl", "resp_ttl", "service", "flags", "conn_state"])
    except Exception as e:
        print("No TCP data:",e)
    udp_fosr = None
    try:
        udp_fosr = pd.read_csv(udp_input, header = 8, engine = "python", skipfooter = 1, sep = "\t", names = ["ts", "uid", "payloads", "iat", "forward_list", "orig_l2_addr", "resp_l2_addr", "orig_ttl", "resp_ttl", "service"])
    except Exception as e:
        print("No UDP data", e)

    print("Services in the TCP file:\n",tcp_fosr["service"].value_counts())
    print("Services in the UDP file:\n",udp_fosr["service"].value_counts())

    print("Extracting")
    flow["Time"] = flow["ts"].apply(functools.partial(categorize_time, args.offset))

    flow["Proto"] = flow["proto"].str.upper()

    # Remove non-UDP and non-TCP flows
    flow = flow[(flow["Proto"]=="TCP") | (flow["Proto"]=="UDP")]

    if tcp_fosr is not None:
        flow = flow.join(tcp_fosr.set_index("uid"), on="uid", rsuffix="_tcp_fosr")
        flow['Connection State'] = flow['conn_state_tcp_fosr']
        flow = flow[(flow["Connection State"]!="other")] # remove rare and OTH connection states
        for v in ["service_tcp_fosr", "orig_l2_addr", "resp_l2_addr"]:
            flow[v] = flow[v].fillna("") # prepare fields for concatenation
        for v in ["orig_ttl", "resp_ttl"]:
            flow[v] = flow[v].replace("-", "999") # marker for absent TTL (for example, no answer in a flow)
            flow[v] = flow[v].fillna("")

    if udp_fosr is not None:
        flow = flow.join(udp_fosr.set_index("uid"), on="uid", rsuffix="_udp_fosr")
        flow["service_udp_fosr"] = flow["service_udp_fosr"].fillna("")
        for v in ["service_udp_fosr", "orig_l2_addr_udp_fosr", "resp_l2_addr_udp_fosr"]:
            flow[v] = flow[v].fillna("")
        for v in ["orig_ttl_udp_fosr", "resp_ttl_udp_fosr"]:
            # TODO: autocomplete: when there is no TTL, fill automatically based on other examples of this IP
            flow[v] = flow[v].replace("-", "64") # default TTL value
            flow[v] = flow[v].fillna("")

    # one or the other will be empty
    flow['Applicative Proto'] = flow['service_tcp_fosr'] + flow['service_udp_fosr']
    flow['Src MAC'] = flow["orig_l2_addr"] + flow["orig_l2_addr_udp_fosr"]
    flow['Dst MAC'] = (flow["resp_l2_addr"] + flow["resp_l2_addr_udp_fosr"])
    flow['Src TTL'] = flow["orig_ttl"].apply(ttl_to_string) + flow["orig_ttl_udp_fosr"].apply(ttl_to_string)
    flow['Dst TTL'] = (flow["resp_ttl"].apply(ttl_to_string) + flow["resp_ttl_udp_fosr"].apply(ttl_to_string))

    # remove flows with unknown service
    flow = flow[flow["Applicative Proto"] != ""]

    # get all the services detected
    services = [s for s in flow['Applicative Proto'].unique() if ":" in s]
    # print("Recognized services:",services)
    # some flow’s protocols may not be corrected infered (S0’s for example). We use the other flows to infer the service
    flow["Applicative Proto"] = flow["Applicative Proto"].apply(functools.partial(complete_proto,services))
    # we remove flows with unknown service
    flow = flow.dropna(subset="Applicative Proto")
    flow['Applicative Proto'] = flow['Applicative Proto'].apply(reorder_services)

    m = 20 # at least 20 examples
    print("Removed rare services:\n",flow["Applicative Proto"].value_counts()[flow["Applicative Proto"].value_counts() < m])
    flow = flow[flow["Applicative Proto"].isin(flow["Applicative Proto"].value_counts()[flow["Applicative Proto"].value_counts() >= m].index)]

    # Export for automata learning

    print("Export for automata learning")
    automata = []
    for s in flow["Applicative Proto"].unique():
        for conn_state in flow[flow["Applicative Proto"] == s]["Connection State"].unique():
            if str(conn_state) != "NaN":
                flows = list(flow[(flow["Applicative Proto"] == s) & (flow["Connection State"] == conn_state) & (flow["Proto"] == "TCP")]["uid"])
                if len(flows) >= m:
                    d = { "service": s, "conn_state": conn_state, "flows": flows, "proto": "tcp" }
                    automata.append(d)
        flows = list(flow[(flow["Applicative Proto"] == s) & (flow["Proto"] == "UDP")]["uid"])
        if len(flows) >= m:
            d = { "service": s, "flows": flows, "proto": "udp" }
            automata.append(d)


    args.output = args.output or "."
    os.makedirs(os.path.join(args.output, "bn"), exist_ok=True)
    out_file = open(os.path.join(args.output, "bn/automata-flows.json"), "w")
    json.dump(automata, out_file, indent=1)

    # Remove flow with more than 200 packets
    flow["Pkts count"] = flow["orig_pkts"] + flow["resp_pkts"]
    flow = flow[flow["Pkts count"] <= 200]

    # get all the local IP addresses
    ips = list(set(flow[flow["local_orig"] == "T"]["id.orig_h"].tolist()).union(set(flow[flow["local_resp"] == "T"]["id.resp_h"].tolist())))
    ips.sort()

    # anonymise public IP
    flow['Src IP Addr'] = flow['id.orig_h'].apply(remove_public_ip, local_ips=ips)
    flow['Dst IP Addr'] = flow['id.resp_h'].apply(remove_public_ip, local_ips=ips)

    # Modify destination ports that only appears once in their own category
    rare_ports = flow["id.resp_p"].value_counts()[flow["id.resp_p"].value_counts() == 1]
    flow['Dst Pt'] = flow['id.resp_p'].apply(port_to_string, rare_ports=rare_ports)

    clients = []
    servers = []

    # ttl = {}

    for ip in ips:
        occurrences_dst = sum(flow["Dst IP Addr"]==ip)
        occurrences_src = sum(flow["Src IP Addr"]==ip)
        if occurrences_src >= occurrences_dst:
            # print(ip,"is a client")
            clients.append(ip)
        else:
            # print(ip,"is a server")
            servers.append(ip)

    #     # broadcast IP will be have no TTL
    #     if ip in ttl_fosr["ip"].values:
    #         # use the most common TTL
    #         ttl[ip] = int(ttl_fosr[ttl_fosr["ip"] == ip]["ttl"].mode()[0])

    # output["ttl"] = ttl
    print("Local clients:",list(clients))
    print("Local servers:",list(servers))

# only for local addresses
    flow['Src IP Role'] = flow['Src IP Addr'].apply(get_network_role, clients=clients, servers=servers)
    flow['Dst IP Role'] = flow['Dst IP Addr'].apply(get_network_role, clients=clients, servers=servers)

    def categorize(out_pkt_count, in_pkt_count):
        best_bic = None
        pkt_count = [[out_pkt_count[i][0],in_pkt_count[i][0]] for i in range(len(out_pkt_count))]
        unique_counts = len(list(set([(l[0],l[1]) for l in pkt_count])))
        pkt_count = np.array(pkt_count)
        for i in range(1,10): # limit on the number of components
            if i > unique_counts: # at most as many components as the number of points
                break
            try:
                m = GaussianMixture(n_components=i, random_state=42, covariance_type="full")
                labels = m.fit_predict(pkt_count)
                bic = m.bic(pkt_count)
                if best_bic is None or best_bic > bic:
                    best_model = m
                    best_bic = bic
                    best_labels = labels
            except Exception as e:
                print("Error during GaussianMixture:",e)

        assert best_bic is not None # at least i==1
        best_labels = list(map(cluster_to_string,best_labels)) # make the variable discrete
        return best_model.means_.tolist(), best_model.covariances_.tolist(), best_labels

    start = time.time()
    output = []

    for s in flow["Applicative Proto"].unique():
        for conn_state in flow[flow["Applicative Proto"] == s]["Connection State"].unique():
            if str(conn_state) != "NaN":
                local_flows = flow[(flow["Applicative Proto"] == s) & (flow["Connection State"] == conn_state) & (flow["Proto"] == "TCP")]
                flows = list(local_flows["uid"])
                if len(flows) >= m:
                    out_pkt_count = np.array(local_flows["orig_pkts"]).reshape(-1,1)
                    in_pkt_count = np.array(local_flows["resp_pkts"]).reshape(-1,1)
                    means, covar, labels = categorize(out_pkt_count, in_pkt_count)
                    flow.loc[(flow['Applicative Proto'] == s) & (flow["Connection State"] == conn_state) & (flow["Proto"] == "TCP"), ["Cat Packet"]] = labels
                    output.append({ "service": s, "conn_state": conn_state, "proto": "TCP", "mu": means, "cov": covar })
        local_flows = flow[(flow["Applicative Proto"] == s) & (flow["Proto"] == "UDP")]
        flows = list(local_flows["uid"])
        if len(flows) >= m:
            out_pkt_count = np.array(local_flows["orig_pkts"]).reshape(-1,1)
            in_pkt_count = np.array(local_flows["resp_pkts"]).reshape(-1,1)
            means, covar, labels = categorize(out_pkt_count, in_pkt_count)
            flow.loc[(flow['Applicative Proto'] == s) & (flow["Proto"] == "UDP"), ["Cat Packet"]] = labels
            output.append({ "service": s, "proto": "UDP", "mu": means, "cov": covar })

    # flows with less than m examples will be removed that way
    flow = flow.dropna(subset=["Cat Packet"])

    flow = flow.replace("-", "none") # "-" causes pyagrum to parse the value as a number, leading to an exception

    flow["Connection State"] = flow["Connection State"].fillna("none")

    all_vars = ["Time", "Applicative Proto", "Proto", "Src IP Addr", "Dst IP Addr", "Dst Pt", "Connection State", "Src TTL", "Dst TTL", "Src MAC", "Dst MAC", "Cat Packet", "Src IP Role", "Dst IP Role"]
    # Extract domains
    for c in all_vars:
        full_domains[c] = [str(s) for s in pd.unique(flow[c])]
        full_domains[c].sort()
    full_domains["Time"] = ["bin-"+f'{n:03}' for n in range(bin_count)] # use all theoretical values

    print("Model learning (for transfer learning)")
    all_vars = ["Time", "Applicative Proto", "Proto", "Connection State", "Cat Packet", "Src IP Role", "Dst IP Role"]
    common_data = flow[all_vars]
    for c in all_vars:
        common_data[c] = common_data[c].astype('category')
        common_data[c] = common_data[c].cat.set_categories(full_domains[c])

    learner = gum.BNLearner(common_data)
    # Time must have no parent because it will be sampled from the stage 1
    learner.addNoParentNode("Time")

    # The categories of packet number depend on the applicative protocol and the connection state, so we ensure that both "Applicative Proto" and "Connection State" are parents of Cat Packet
    learner.addMandatoryArc("Applicative Proto", "Cat Packet")
    learner.addMandatoryArc("Connection State", "Cat Packet")

    # After some experimentations, the impact of the method and score is negligible
    learner.useMIIC()

    bn = learner.learnBN()

    # we recreate the bayesian network with the same structure but the full domain
    bn_full = gum.BayesNet('Fos-R model (TL)')
    for i in bn.nodes():
        var = bn.variable(i).name()
        bn_full.add(gum.LabelizedVariable(var, var, full_domains[var]))

    for i in bn.nodes():
        parents = bn.parents(i)
        for p in parents:
            bn_full.addArc(p, i)

    parameters_learning(bn_full, common_data)
    bn = bn_full

    print("Learning time:", time.time() - start)
    print("Model export")

    gumimage.export(bn, os.path.join(args.output, "bn/bn_tl.png"))
    gumimage.export(bn, os.path.join(args.output, "bn/bn_tl.ps"))
    bn.saveBIFXML(os.path.join(args.output, "bn/bn_tl.bifxml"))

    try:
        out_file = open(os.path.join(args.output, "pkt_count_clusters_tl.json"), "w")
        json.dump(output, out_file, indent=1)
        print("JSON file successfully created")
    except Exception as e:
        print("Error during json save:",e)


    print("Model learning")

    all_vars = ["Time", "Applicative Proto", "Proto", "Src IP Addr", "Dst IP Addr", "Dst Pt", "Connection State", "Src TTL", "Dst TTL", "Src MAC", "Dst MAC", "Cat Packet"]
    common_data = flow[all_vars]
    for c in all_vars:
        common_data[c] = common_data[c].astype('category')
        common_data[c] = common_data[c].cat.set_categories(full_domains[c])

    learner = gum.BNLearner(common_data)
    # Time must have no parent because it will be sampled from the stage 1
    learner.addNoParentNode("Time")

    # The categories of packet number depend on the applicative protocol and the connection state, so we ensure that both "Applicative Proto" and "Connection State" are parents of Cat Packet
    learner.addMandatoryArc("Applicative Proto", "Cat Packet")
    learner.addMandatoryArc("Connection State", "Cat Packet")

    # After some experimentations, the impact of the method and score is negligible
    learner.useMIIC()

    bn = learner.learnBN()

    # we recreate the bayesian network with the same structure but the full domain
    bn_full = gum.BayesNet('Fos-R model')
    for i in bn.nodes():
        var = bn.variable(i).name()
        bn_full.add(gum.LabelizedVariable(var, var, full_domains[var]))

    for i in bn.nodes():
        parents = bn.parents(i)
        for p in parents:
            bn_full.addArc(p, i)

    parameters_learning(bn_full, common_data)
    bn = bn_full

    print("Learning time:", time.time() - start)
    print("Model export")

    gumimage.export(bn, os.path.join(args.output, "bn/bn.png"))
    gumimage.export(bn, os.path.join(args.output, "bn/bn.ps"))
    bn.saveBIFXML(os.path.join(args.output, "bn/bn.bifxml"))

    try:
        out_file = open(os.path.join(args.output, "pkt_count_clusters.json"), "w")
        json.dump(output, out_file, indent=1)
        print("JSON file successfully created")
    except Exception as e:
        print("Error during json save:",e)

