# Data to generate: src_ip, dst_ip, src_port, dst_port, ttl_client, ttl_server, fwd_pckets_count, bwd_packets_count, proto

import argparse
import numpy as np
import pandas as pd
import random
from sklearn.mixture import GaussianMixture
import json
import pyagrum as gum

def group_flags(value):
    value = str(value)
    if '......'==value:
        return 'None'
    elif 'R' in value:
        return 'R'
    elif 'F' in value:
        return 'F and not R'
    else:
        return 'not F and not R'

# TODO: find a more complete list online
Dst_Pt_mapping = {
    53.0: 'DNS',
    443.0: 'HTTPS',
    80.0: 'HTTP',
    137.0: 'Netbios',
    138.0: 'Netbios',
    8082.0: 'HTTP',
    8000.0: 'HTTP',
    5353.0: 'Multicast DNS',
    1900.0: 'SSDP',
    25.0: 'SMTP',
    67.0: 'DHCP',
    993.0: 'IMAPS',
    587.0: 'SMTP',
    445.0: 'SMB',
    0.0: 'Local',
    3544.0: 'Teredo',
    8088:'HTTP',
    8612.0: 'Canon-bjmp',
    22.0: 'SSH',
    3702.0: 'WSD',
    123.0: 'NTP',
    8080.0: 'HTTP',
    8081.0: 'HTTP',
    1688.0: 'KMS',

}

# TODO: generate config file for each dataset

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

# specific to CIDDS
# def deanonymise_ip(value):
#     if "_" in value:
#         random.seed(value)
#         return ".".join(str(random.randint(0, 255)) for _ in range(4))

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
    # TODO: formatter la string pour qu’elle ait toujours la même taille, ainsi ordre numérique = ordre alphabétique
    return "bin-"+str(t % (1000000000*60*60*24) // (1000000000*60*60*24 / bin_count))

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

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Learn a time profile for Fos-R.')
    parser.add_argument('--input', required=True, help="Select the input file. It must a csv.")
    # parser.add_argument('--output', help="Select the output file to create.")
    args = parser.parse_args()

    random.seed(0)

    output = {}
    output["s0_bin_count"] = bin_count

    # args.input = "cidds.csv"

    flow = pd.read_csv(args.input, header = 0, sep = ",")

    flow["Time"] = flow["Date first seen"].apply(categorize_time)

    flow["Proto"] = flow["Proto"].str.strip()
    # Remove non-UDP and non-TCP flows
    flow = flow[(flow["Proto"]=="TCP") | (flow["Proto"]=="UDP")]

    flow['End Flags'] = flow['Flags'].apply(group_flags)
    flow['Applicative Proto'] = flow['Dst Pt'].map(Dst_Pt_mapping)
    flow['Src IP Addr'] = flow['Src IP Addr'].apply(remove_public_ip)
    flow['Dst IP Addr'] = flow['Dst IP Addr'].apply(remove_public_ip)
    flow['Dst Pt'] = flow['Dst Pt'].apply(to_string)
    # flow['Dst Pt'] = flow['Dst Pt'].astype('str')
    # print(flow['Dst Pt'])

    # Only keep the most common protocols (TODO: lift that restriction)
    flow = flow[flow['Applicative Proto'].isin(["DNS", "HTTP", "HTTPS", "SMTP", "DHCP", "IMAPS", "SSH", "NTP"])]

    # get all the local IP addresses
    ips = set(flow["Src IP Addr"].tolist()).union(set(flow["Dst IP Addr"].tolist()))
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
        ttl[ip] = 64 - random.randint(1,4) # TODO should be measured !

    output["ttl"] = ttl
    print("Local clients:",list(clients))
    print("Local servers:",list(servers))


# only for local addresses
    flow['Src IP Role'] = flow['Src IP Addr'].apply(get_network_role, clients=clients, servers=servers)
    flow['Dst IP Role'] = flow['Dst IP Addr'].apply(get_network_role, clients=clients, servers=servers)

    TCP_out_pkt_count = np.array(flow[flow['Proto']=="TCP"]["Out Packet"]).reshape(-1,1)
    TCP_in_pkt_count = np.array(flow[flow['Proto']=="TCP"]["In Packet"]).reshape(-1,1)
    UDP_out_pkt_count = np.array(flow[flow['Proto']=="UDP"]["Out Packet"]).reshape(-1,1)
    UDP_in_pkt_count = np.array(flow[flow['Proto']=="UDP"]["In Packet"]).reshape(-1,1)

    def categorize(pkt_count):
        best_bic = None
        for i in range(5): # limit on the number of components
            if i+1 > len(pkt_count): # at most as many components as the number of points
                break
            m = GaussianMixture(n_components=i+1, random_state=42, covariance_type="spherical")
            labels = m.fit_predict(pkt_count)
            bic = m.bic(pkt_count)
            if best_bic is None or best_bic > bic:
                best_model = m
                best_bic = bic
                best_labels = labels
        best_labels = list(map(str,best_labels)) # make the variable discrete
        return best_model.means_.reshape(1,-1)[0], best_model.covariances_, best_labels

    print("Gaussian mixture for TCP out packet count")
    mu, cov, labels = categorize(TCP_out_pkt_count)
    output["tcp_out_pkt_gaussians"] = {"mu": mu.tolist(), "cov": cov.tolist()}
    flow.loc[flow['Proto']=="TCP", ["Cat Out Packet"]] = labels

    print("Gaussian mixture for TCP in packet count")
    mu, cov, labels = categorize(TCP_in_pkt_count)
    output["tcp_in_pkt_gaussians"] = {"mu": mu.tolist(), "cov": cov.tolist()}
    flow.loc[flow['Proto']=="TCP", ["Cat In Packet"]] = labels

    print("Gaussian mixture for UDP out packet count")
    mu, cov, labels = categorize(UDP_out_pkt_count)
    output["udp_out_pkt_gaussians"] = {"mu": mu.tolist(), "cov": cov.tolist()}
    flow.loc[flow['Proto']=="UDP", ["Cat Out Packet"]] = labels

    print("Gaussian mixture for UDP in packet count")
    mu, cov, labels = categorize(UDP_in_pkt_count)
    output["udp_in_pkt_gaussians"] = {"mu": mu.tolist(), "cov": cov.tolist()}
    flow.loc[flow['Proto']=="UDP", ["Cat In Packet"]] = labels

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
        # End flags

    tcp_vars = ["Cat Out Packet", "Cat In Packet", "End Flags"]
    tcp_data = flow[flow['Proto']=="TCP"]
    tcp_data = flow[tcp_vars + common_vars]

    # UDP-only variables:
        # In Pkt Count
        # Out Pkt Count

    udp_vars = ["Cat Out Packet", "Cat In Packet"]
    udp_data = flow[flow['Proto']=="UDP"]
    udp_data = flow[udp_vars + common_vars]

    # Variables not used during structure learning (saved as dictionaries alongside the BN)
        # Dst Port
        # Src IP Addr
        # Dst IP Addr

    print("Model learning")

    # TODO: lors de l’apprentissage de paramètre, ne pas utiliser de prior

    learner_common = gum.BNLearner(common_data)
    # learner1.addMandatoryArc("Departements", "Proto App")
    # learner1.addMandatoryArc("Localisation", "Proto App")
    # Time must have no parent because it will be sampled from the stage 0
    learner_common.addNoParentNode("Time") # variable with no parent
    # Src IP Addr and Dst IP Addr must have no children because we want to modify their CPT with the configuration file
    for var in vars_without_children:
        learner_common.addNoChildrenNode(var) # variable with no children

    learner_common.useMIIC()
    bn_common = learner_common.learnBN()
    ParametersLearning(bn_common, common_data)

    learner_udp = gum.BNLearner(udp_data)
    for var in common_vars:
        learner_udp.addNoParentNode(var) # variable with no parent
    for var in vars_without_children:
        learner_udp.addNoChildrenNode(var) # variable with no children

    learner_udp.useMIIC()
    bn_udp = learner_udp.learnBN()
    ParametersLearning(bn_udp, udp_data)

    learner_tcp = gum.BNLearner(tcp_data)
    for var in common_vars:
        learner_tcp.addNoParentNode(var) # variable with no parent
    for var in vars_without_children:
        learner_tcp.addNoChildrenNode(var) # variable with no children

    learner_tcp.useMIIC()
    bn_tcp = learner_tcp.learnBN()
    ParametersLearning(bn_tcp, tcp_data)

    print("Model export")

    bn_common.saveBIFXML("bn_common.bifxml")
    bn_udp.saveBIFXML("bn_udp.bifxml")
    bn_tcp.saveBIFXML("bn_tcp.bifxml")

    print(output)
    try:
        out_file = open("bn_additional_data.json", "w")
        json.dump(output, out_file)
        print("JSON file successfully created")
    except Exception as e:
        print("Error during json save:",e)

