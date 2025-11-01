# Data to generate: src_ip, dst_ip, src_port, dst_port, ttl_client, ttl_server, fwd_pckets_count, bwd_packets_count, proto

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

def group_ip_dst(value):
    value = str(value)
    local_net = ['192.168.', '10.', '0.', '127.', '172.', '192.0.0', '198.18', '198.19']
    for ip in local_net:
        if value.startswith(ip):
            return 'Local'
    return 'Internet'

def get_network_role(ip, clients, servers):
    if ip in clients:
        return "Client"
    elif ip in servers:
        return "Server"
    else:
        return "Internet"

bin_count = 24*4

def categorize_time(t):
    return "bin-"+str(t % (1000000000*60*60*24) // (1000000000*60*60*24 / bin_count))

if __name__ == '__main__':
    random.seed(0)

    output = {}
    output["s0_bin_count"] = bin_count

    flow = pd.read_csv("cidds.csv", header = 0, sep = ",")

    flow["Time"] = flow["Date first seen"].apply(categorize_time)

    flow["Proto"] = flow["Proto"].str.strip()
    # Remove non-UDP and non-TCP flows
    flow = flow[(flow["Proto"]=="TCP") | (flow["Proto"]=="UDP")]

    flow['End Flags'] = flow['Flags'].apply(group_flags)
    flow['Applicative Proto'] = flow['Dst Pt'].map(Dst_Pt_mapping)

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
    output["TCP_out_pkt_gaussians"] = {"mu": mu.tolist(), "cov": cov.tolist()}
    flow.loc[flow['Proto']=="TCP", ["Cat Out Packet"]] = labels

    print("Gaussian mixture for TCP in packet count")
    mu, cov, labels = categorize(TCP_in_pkt_count)
    output["TCP_in_pkt_gaussians"] = {"mu": mu.tolist(), "cov": cov.tolist()}
    flow.loc[flow['Proto']=="TCP", ["Cat In Packet"]] = labels

    print("Gaussian mixture for UDP out packet count")
    mu, cov, labels = categorize(UDP_out_pkt_count)
    output["UDP_out_pkt_gaussians"] = {"mu": mu.tolist(), "cov": cov.tolist()}
    flow.loc[flow['Proto']=="UDP", ["Cat Out Packet"]] = labels

    print("Gaussian mixture for UDP in packet count")
    mu, cov, labels = categorize(UDP_in_pkt_count)
    output["UDP_in_pkt_gaussians"] = {"mu": mu.tolist(), "cov": cov.tolist()}
    flow.loc[flow['Proto']=="UDP", ["Cat In Packet"]] = labels

    # Common variables:
        # Src IP Role
        # Dst IP Role
        # Applicative Protocol
    common_vars = ["Time", "Src IP Role", "Dst IP Role", "Applicative Proto"]
    common_data = flow[common_vars]

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
        # Proto

    print("Model learning")

    learner_common = gum.BNLearner(common_data)
    # learner1.addMandatoryArc("Departements", "Proto App")
    # learner1.addMandatoryArc("Localisation", "Proto App")
    learner_common.addNoParentNode("Time") # variable with no parent
    learner_common.useMIIC()
    bn_common = learner_common.learnBN()

    learner_udp = gum.BNLearner(udp_data)
    for var in common_vars:
        learner_udp.addNoParentNode(var) # variable with no parent
    learner_udp.useMIIC()
    bn_udp = learner_udp.learnBN()

    learner_tcp = gum.BNLearner(tcp_data)
    for var in common_vars:
        learner_tcp.addNoParentNode(var) # variable with no parent
    learner_tcp.useMIIC()
    bn_tcp = learner_tcp.learnBN()

    print("Model export")

    bn_common.saveBIFXML("bn_common.bifxml")
    bn_udp.saveBIFXML("bn_udp.bifxml")
    bn_tcp.saveBIFXML("bn_tcp.bifxml")

    print(output)
    try:
        out_file = open("bn-additional-data.json", "w")
        json.dump(output, out_file)
        print("JSON file successfully created")
    except Exception as e:
        print("Error during json save:",e)

