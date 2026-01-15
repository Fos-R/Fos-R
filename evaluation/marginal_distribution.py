import os
import argparse
import pandas as pd
import numpy as np
from math import log2
from scipy.stats import wasserstein_distance

def merge_internet(value):
    # TODO: use "local_orig" et "local_resp" plutôt
    value = str(value)
    local_net = ['192.168.', '10.', '0.', '127.', '172.', '192.0.0', '198.18', '198.19']
    for ip in local_net:
        if value.startswith(ip):
            return value
    return 'Internet'


def jsd(l1, l2):
    val1, count1 = np.unique(l1, return_counts=True)
    val2, count2 = np.unique(l2, return_counts=True)
    # normalization
    count1 = count1 / sum(count1)
    count2 = count2 / sum(count2)

    all_val = set(val1).union(set(val2))
    score = 0
    for v in all_val:
        try:
            index = list(val1).index(v)
            p1 = count1[index]
        except:
            p1 = 0
        try:
            index = list(val2).index(v)
            p2 = count2[index]
        except:
            p2 = 0

        m = 0.5 * (p1 + p2)
        if p1 > 0:
            score += 0.5 * p1 * log2(p1 / m)
        if p2 > 0:
            score += 0.5 * p2 * log2(p2 / m)
    return score

def emd(l1, l2):
    return wasserstein_distance(l1, l2)

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Learn a time profile for Fos-R.')
    parser.add_argument('--real', required=True, help="Select the folder with Zeek logs of real data.")
    parser.add_argument('--synthetic', help="Select the folder with Zeek logs of synthetic data.")
    args = parser.parse_args()

    try:
        flow_real = pd.read_csv(os.path.join(args.real, "conn.log"), header = 8, engine = "python", skipfooter = 1, sep = "\t", names = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp", "missed_bytes", "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "tunnel_parents", "ip_proto"])
        flow_synthetic = pd.read_csv(os.path.join(args.synthetic, "conn.log"), header = 8, engine = "python", skipfooter = 1, sep = "\t", names = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp", "missed_bytes", "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "tunnel_parents", "ip_proto"])
    except Exception as e:
        print(f"Cannot find conn.log!",e)
        exit(1)

    print("JSD\n===")
    print("Source IP",jsd(flow_real["id.orig_h"].apply(merge_internet),flow_synthetic["id.orig_h"].apply(merge_internet)))
    print("Dest. IP",jsd(flow_real["id.resp_h"].apply(merge_internet),flow_synthetic["id.resp_h"].apply(merge_internet)))
    print("Dest. port",jsd(flow_real["id.resp_p"],flow_synthetic["id.resp_p"]))
    print("Protocol",jsd(flow_real["proto"],flow_synthetic["proto"]))
    print("Service",jsd(flow_real["service"],flow_synthetic["service"]))
    print("History",jsd(flow_real["history"],flow_synthetic["history"]))
    # we only consider connections with a connection state (i.e., TCP)
    print("Connection state",jsd(flow_real[flow_real["conn_state"] != "-"]["conn_state"],flow_synthetic[flow_synthetic["conn_state"] != "-"]["conn_state"]))
    print("IP protocol",jsd(flow_real["ip_proto"],flow_synthetic["ip_proto"]))
    print("\nEMD\n===")
    print("Duration",emd(flow_real["duration"].replace("-", "0"),flow_synthetic["duration"].replace("-", "0")))
    print("Source bytes",emd(flow_real["orig_bytes"].replace("-", "0"),flow_synthetic["orig_bytes"].replace("-", "0")))
    print("Dest. bytes",emd(flow_real["resp_bytes"].replace("-", "0"),flow_synthetic["resp_bytes"].replace("-", "0")))
    print("Source packets",emd(flow_real["orig_pkts"].replace("-", "0"),flow_synthetic["orig_pkts"].replace("-", "0")))
    print("Dest. packets",emd(flow_real["resp_pkts"].replace("-", "0"),flow_synthetic["resp_pkts"].replace("-", "0")))

