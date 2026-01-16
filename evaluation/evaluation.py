import os
import argparse
import pandas as pd
import numpy as np
from math import log2
from scipy.stats import wasserstein_distance
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder

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

def evaluate(flow_real, flow_synthetic):
    results = {}

    # JSD for categorical data
    results["Source IP"] = jsd(flow_real["id.orig_h"],flow_synthetic["id.orig_h"])
    results["Dest. IP"] = jsd(flow_real["id.resp_h"],flow_synthetic["id.resp_h"])
    results["Dest. port"] = jsd(flow_real["id.resp_p"],flow_synthetic["id.resp_p"])
    results["Protocol"] = jsd(flow_real["proto"],flow_synthetic["proto"])
    results["Service"] = jsd(flow_real["service"],flow_synthetic["service"])
    results["History"] = jsd(flow_real["history"],flow_synthetic["history"])
    # we only consider connections with a connection state (i.e., TCP)
    results["Connection state"] = jsd(flow_real[flow_real["conn_state"] != "-"]["conn_state"],flow_synthetic[flow_synthetic["conn_state"] != "-"]["conn_state"])
    results["IP protocol"] = jsd(flow_real["ip_proto"],flow_synthetic["ip_proto"])

    # EMD for numerical data
    results["Duration"] = wasserstein_distance(flow_real["duration"],flow_synthetic["duration"])
    results["Source bytes"] = wasserstein_distance(flow_real["orig_bytes"],flow_synthetic["orig_bytes"])
    results["Dest. bytes"] = wasserstein_distance(flow_real["resp_bytes"],flow_synthetic["resp_bytes"])
    results["Source packets"] = wasserstein_distance(flow_real["orig_pkts"],flow_synthetic["orig_pkts"])
    results["Dest. packets"] = wasserstein_distance(flow_real["resp_pkts"],flow_synthetic["resp_pkts"])

    flow_real_if = flow_real[["id.orig_h", "id.resp_h", "id.resp_p", "proto", "service", "history", "conn_state", "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"]]
    flow_synthetic_if = flow_synthetic[["id.orig_h", "id.resp_h", "id.resp_p", "proto", "service", "history", "conn_state", "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"]]

    for feature in ["id.orig_h", "id.resp_h", "proto", "service", "history", "conn_state"]:
        le = LabelEncoder().fit(list(flow_real_if[feature])+list(flow_synthetic_if[feature]))
        flow_real_if[feature] = le.transform(flow_real_if[feature])
        flow_synthetic_if[feature] = le.transform(flow_synthetic_if[feature])

    # Is the synthetic included in the real data? i.e., realism
    clf = IsolationForest(random_state=0, max_samples=1.0).fit(flow_real_if)
    anomalies = [1 if s == -1 else 0 for s in clf.predict(flow_synthetic_if)]
    results["Realism:"] = 1-sum(anomalies)/len(anomalies)

    # Is the real included in the synthetic data? i.e., diversity
    clf = IsolationForest(random_state=0, max_samples=1.0).fit(flow_synthetic_if)
    anomalies = [1 if s == -1 else 0 for s in clf.predict(flow_real_if)]
    results["Diversity:"] = 1-sum(anomalies)/len(anomalies)

    return results

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Learn a time profile for Fos-R.')
    parser.add_argument('--eval', required=True, help="Select the folder with Zeek logs of real data.")
    parser.add_argument('--reference', required=True, help="Select the folder with Zeek logs of real data.")
    parser.add_argument('--synthetic', help="Select the folder with Zeek logs of synthetic data.")
    args = parser.parse_args()

    try:
        flow_eval = pd.read_csv(os.path.join(args.eval, "conn.log"), header = 8, engine = "python", skipfooter = 1, sep = "\t", names = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp", "missed_bytes", "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "tunnel_parents", "ip_proto"])
        flow_ref = pd.read_csv(os.path.join(args.reference, "conn.log"), header = 8, engine = "python", skipfooter = 1, sep = "\t", names = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp", "missed_bytes", "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "tunnel_parents", "ip_proto"])
        flow_synthetic = pd.read_csv(os.path.join(args.synthetic, "conn.log"), header = 8, engine = "python", skipfooter = 1, sep = "\t", names = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp", "missed_bytes", "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "tunnel_parents", "ip_proto"])
    except Exception as e:
        print(f"Cannot find conn.log!",e)
        exit(1)

    # preprocessing
    for feature in ["id.orig_h", "id.resp_h"]:
        flow_eval[feature] = flow_eval[feature].apply(merge_internet)
        flow_ref[feature] = flow_ref[feature].apply(merge_internet)
        flow_synthetic[feature] = flow_synthetic[feature].apply(merge_internet)

    for feature in ["duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"]:
        flow_eval[feature] = flow_eval[feature].replace("-", "0")
        flow_ref[feature] = flow_ref[feature].replace("-", "0")
        flow_synthetic[feature] = flow_synthetic[feature].replace("-", "0")

        flow_eval[feature] = pd.to_numeric(flow_eval[feature])
        flow_eval[feature] = (flow_eval[feature] - flow_eval[feature].mean()) / flow_eval[feature].std()

        flow_ref[feature] = pd.to_numeric(flow_ref[feature])
        flow_ref[feature] = (flow_ref[feature] - flow_ref[feature].mean()) / flow_ref[feature].std()

        flow_synthetic[feature] = pd.to_numeric(flow_synthetic[feature])
        flow_synthetic[feature] = (flow_synthetic[feature] - flow_synthetic[feature].mean()) / flow_synthetic[feature].std()


    results_synthetic = evaluate(flow_eval, flow_synthetic)
    results_ref = evaluate(flow_eval, flow_ref)

    for k,v in results_ref.items():
        print(f"{k}:\n\tReference: {v}\n\tSynthetic: {results_synthetic[k]}\n\tDelta: {abs(results_synthetic[k] - v)}")
