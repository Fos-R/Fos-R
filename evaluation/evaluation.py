#!/usr/bin/env python3

import os
import argparse
import pandas as pd
import numpy as np
from math import log2
from scipy.stats import wasserstein_distance
from sklearn.preprocessing import LabelEncoder
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.metrics import balanced_accuracy_score
from sklearn.manifold import TSNE
from sklearn.metrics.pairwise import cosine_similarity
from scipy.spatial.distance import hamming
import bleu
import rouge
from vendi_score import vendi
import json
from scipy import stats
from sklearn.metrics import mutual_info_score

pd.options.mode.copy_on_write = True

def keep_first_service(value):
    return value.split(",")[0]

local_net = ['192.168.', '10.', '0.', '127.', '192.0.0', '198.18', '198.19']
for i in range(16,32):
    local_net.append("172."+str(i)+".")

def merge_internet(value):
    # TODO: use "local_orig" et "local_resp" plutôt
    value = str(value)
    for ip in local_net:
        if value.startswith(ip):
            return value
    return 'Internet'

def get_time(value):
    return value % (3600 * 24)

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

def evaluate_tcp(flow_real, flow_synthetic):
    print("Evaluating TCP packet-level metrics")
    return [ {"data": "Packet", "feature": "TCP flags", "metric": "JSD", "value": jsd(flow_real["tcp.flags"],flow_synthetic["tcp.flags"])} ]

def evaluate_ip(flow_real, flow_synthetic):
    print("Evaluating IP packet-level metrics")
    results = []
    results.append({"data": "Packet", "feature": "TTL", "metric": "JSD", "value": jsd(flow_real["ip.ttl"],flow_synthetic["ip.ttl"])})
    results.append({"data": "Packet", "feature": "Source IP", "metric": "JSD", "value": jsd(flow_real["ip.src"],flow_synthetic["ip.src"])})
    results.append({"data": "Packet", "feature": "Dest. IP", "metric": "JSD", "value": jsd(flow_real["ip.dst"],flow_synthetic["ip.dst"])})
    results.append({"data": "Packet", "feature": "L4 Protocol", "metric": "JSD", "value": jsd(flow_real["ip.proto"],flow_synthetic["ip.proto"])})
    results.append({"data": "Packet", "feature": "Length", "metric": "EMD", "value": wasserstein_distance(flow_real["ip.len"],flow_synthetic["ip.len"])})
    return results

def evaluate_pcap(pcap_real, pcap_synthetic):
    results = []
    print("Evaluating BLEU")
    results.append({"data": "Pcap file", "feature": "n-grams", "metric": "BLEU", "value": bleu.compute_bleu(translation_corpus=[list(pcap_synthetic)], reference_corpus=[[list(pcap_real)]], max_order=4)[0]})
    print("Evaluating ROUGE")
    results.append({"data": "Pcap file", "feature": "n-grams", "metric": "ROUGE", "value": rouge.rouge_n(evaluated_sentences=list(pcap_synthetic), reference_sentences=list(pcap_eval), n=4)[0]})
    results.append({"data": "Pcap file", "feature": "Bytes histograms", "metric": "JSD", "value": jsd(list(pcap_real), list(pcap_synthetic))})
    return results

def evaluate_weird(flow_real, flow_synthetic, flow_real_weird, flow_synthetic_weird):
    results = []
    print("Evaluating weird.log file")
    results.append({"data": "Flow", "feature": "\"Weird\" occurrences ", "metric": "Ratio difference", "value": len(flow_synthetic_weird) / len(flow_synthetic) - len(flow_real_weird) / len(flow_real)})
    print("Most common names in weird.log:")
    print(flow_synthetic_weird["name"].value_counts())
    return results

def evaluate_flow(flow_real, flow_synthetic):
    results = []

    # JSD for categorical data
    print("Evaluating flow-level metrics")
    results.append({"data": "Flow", "feature": "Source IP", "metric": "JSD", "value": jsd(flow_real["id.orig_h"],flow_synthetic["id.orig_h"])})
    results.append({"data": "Flow", "feature": "Dest. IP", "metric": "JSD", "value": jsd(flow_real["id.resp_h"],flow_synthetic["id.resp_h"])})
    results.append({"data": "Flow", "feature": "Dest. Port", "metric": "JSD", "value": jsd(flow_real["id.resp_p"],flow_synthetic["id.resp_p"])})
    results.append({"data": "Flow", "feature": "L4 Protocol", "metric": "JSD", "value": jsd(flow_real["proto"],flow_synthetic["proto"])})
    results.append({"data": "Flow", "feature": "L7 Protocol", "metric": "JSD", "value": jsd(flow_real["service"],flow_synthetic["service"])})
    results.append({"data": "Flow", "feature": "Flags History", "metric": "JSD", "value": jsd(flow_real["history"],flow_synthetic["history"])})
    # we only consider connections with a connection state (i.e., TCP)
    results.append({"data": "Flow", "feature": "Connection State", "metric": "JSD", "value": jsd(flow_real[flow_real["conn_state"] != "-"]["conn_state"],flow_synthetic[flow_synthetic["conn_state"] != "-"]["conn_state"])})
    results.append({"data": "Flow", "feature": "L3 Protocol", "metric": "JSD", "value": jsd(flow_real["ip_proto"],flow_synthetic["ip_proto"])})

    # EMD for numerical data
    results.append({"data": "Flow", "feature": "Duration", "metric": "EMD", "value": wasserstein_distance(flow_real["duration"],flow_synthetic["duration"])})
    results.append({"data": "Flow", "feature": "Source Bytes", "metric": "EMD", "value": wasserstein_distance(flow_real["orig_bytes"],flow_synthetic["orig_bytes"])})
    results.append({"data": "Flow", "feature": "Dest. Bytes", "metric": "EMD", "value": wasserstein_distance(flow_real["resp_bytes"],flow_synthetic["resp_bytes"])})
    results.append({"data": "Flow", "feature": "Source Packets", "metric": "EMD", "value": wasserstein_distance(flow_real["orig_pkts"],flow_synthetic["orig_pkts"])})
    results.append({"data": "Flow", "feature": "Dest. Packets", "metric": "EMD", "value": wasserstein_distance(flow_real["resp_pkts"],flow_synthetic["resp_pkts"])})
    # results["Flow Time"] = wasserstein_distance(flow_real["ts"],flow_synthetic["ts"])

    nice_names = {"duration": "Duration", "orig_bytes": "Source Bytes", "resp_bytes": "Dest. Bytes", "orig_pkts": "Source Packets", "resp_pkts": "Dest. Packets", "id.orig_h": "Source IP", "id.resp_h": "Dest. IP", "id.resp_p": "Dest. Port", "proto": "L4 Protocol", "service": "L7 Protocol", "history": "Flags History", "conn_state": "Connection State", "ip_proto": "L3 Protocol"}

    # # Spearman correlation for numerical data
    # for (i,f1) in enumerate(["duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"]):
    #     for (j,f2) in enumerate(["duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"]):
    #         if i < j:
    #             results.append({"data": "Flow", "feature": f"{nice_names[f1]} & {nice_names[f2]}", "metric": "Spearman corr. difference", "value": stats.spearmanr(flow_synthetic[f1], flow_synthetic[f2]).statistic - stats.spearmanr(flow_real[f1], flow_real[f2]).statistic})

    # # Mutual information for categorical data
    # for (i,f1) in enumerate(["id.orig_h", "id.resp_h", "id.resp_p", "proto", "service","history", "conn_state", "ip_proto"]):
    #     for (j,f2) in enumerate(["id.orig_h", "id.resp_h", "id.resp_p", "proto", "service","history", "conn_state", "ip_proto"]):
    #         if i < j:
    #             results.append({"data": "Flow", "feature": f"{nice_names[f1]} & {nice_names[f2]}", "metric": "Mutual Information", "value":  mutual_info_score(flow_synthetic[f1], flow_synthetic[f2]) - mutual_info_score(flow_real[f1], flow_real[f2])})

    discrete_similarity = lambda l1, l2: 1-hamming(l1,l2)

    print("Evaluating Vendi scores")
    # use only 1000 flows chosen randomly
    discrete_samples_synthetic = flow_synthetic[["id.orig_h", "id.resp_h", "id.resp_p", "proto", "service","history", "conn_state", "ip_proto"]].sample(n=1000, random_state=0).values.tolist()
    # Vendi describes a dataset and is not a distance.
    results.append({"data": "Flow", "feature": "All Discrete Features", "metric": "Vendi", "value": vendi.score(discrete_samples_synthetic, discrete_similarity) / len(discrete_samples_synthetic)})

    continuous_samples_synthetic = flow_synthetic[["duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"]].sample(n=1000, random_state=0)
    # normalize
    for column in continuous_samples_synthetic.columns:
        continuous_samples_synthetic[column] = (continuous_samples_synthetic[column] - continuous_samples_synthetic[column].mean()) / continuous_samples_synthetic[column].std()
    continuous_samples_synthetic = continuous_samples_synthetic.values.tolist()
    results.append({"data": "Flow", "feature": "All Continuous Features", "metric": "Vendi", "value": vendi.score_K(cosine_similarity(continuous_samples_synthetic)) / len(discrete_samples_synthetic)})

    print("Evaluating C2ST")

    # transform to numeric
    flow_real_c2st = flow_real.copy(deep=True)
    flow_synthetic_c2st = flow_synthetic.copy(deep=True)
    for feature in ["id.orig_h", "id.resp_h", "id.resp_p", "proto", "service", "history", "conn_state", "local_orig", "local_resp"]:
        le = LabelEncoder().fit(list(flow_real[feature])+list(flow_synthetic[feature]))
        flow_real_c2st[feature] = le.transform(flow_real[feature])
        flow_synthetic_c2st[feature] = le.transform(flow_synthetic[feature])

    X_train, X_test, y_train, y_test = train_test_split(pd.concat([flow_real_c2st[["id.orig_h", "id.resp_h", "id.resp_p", "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp", "missed_bytes", "history", "orig_pkts", "resp_pkts"]], flow_synthetic_c2st[["id.orig_h", "id.resp_h", "id.resp_p", "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp", "missed_bytes", "history", "orig_pkts", "resp_pkts"]]]), [0]*len(flow_real)+[1]*len(flow_synthetic), test_size=0.2, random_state=42)

    clf = RandomForestClassifier(random_state=0)
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)

    results.append({"data": "Flow", "feature": "All Features", "metric": "C2ST Balanced Accuracy", "value": balanced_accuracy_score(y_test, y_pred)})

    return results

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Evaluate the generated data.')
    parser.add_argument('--eval', required=True, help="Select the folder with Zeek logs of evaluation data.")
    parser.add_argument('--reference', required=True, help="Select the folder with Zeek logs of reference data.")
    parser.add_argument('--synthetic', required=True, help="Select the folder with Zeek logs of synthetic data.")
    parser.add_argument('--synthetic-name', required=True, help="The name of the synthetic data.")
    # parser.add_argument('--baseline', choices=["naive","ros","smote","adasyn"], help="Select a baseline to run")
    # parser.add_argument('--baseline-train', help="Select the folder with Zeek logs of train data.")
    parser.add_argument('--output', required=True, help="Output directory.")
    args = parser.parse_args()

    try:
        os.mkdir(args.output)
    except FileExistsError:
        pass
    except Exception as e:
        print(f"An error occurred: {e}")
        exit()

    # normalize the paths
    args.eval = os.path.normpath(args.eval)
    args.synthetic = os.path.normpath(args.synthetic)
    args.reference = os.path.normpath(args.reference)

    print("Loading data")
    # conn.log
    try:
        flow_eval = pd.read_csv(os.path.join(args.eval, "conn.log"), header = 8, engine = "python", skipfooter = 1, sep = "\t", names = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp", "missed_bytes", "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "tunnel_parents", "ip_proto"])
        flow_ref = pd.read_csv(os.path.join(args.reference, "conn.log"), header = 8, engine = "python", skipfooter = 1, sep = "\t", names = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp", "missed_bytes", "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "tunnel_parents", "ip_proto"])
        flow_synthetic = pd.read_csv(os.path.join(args.synthetic, "conn.log"), header = 8, engine = "python", skipfooter = 1, sep = "\t", names = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp", "missed_bytes", "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "tunnel_parents", "ip_proto"])
        # elif args.baseline_train:
        #     flow_synthetic = pd.read_csv(os.path.join(args.baseline_train, "conn.log"), header = 8, engine = "python", skipfooter = 1, sep = "\t", names = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp", "missed_bytes", "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "tunnel_parents", "ip_proto"])
    except Exception as e:
        print(f"Cannot process conn.log!",e)
        exit(1)


    flow_eval['service'] = flow_eval['service'].apply(keep_first_service)
    flow_ref['service'] = flow_ref['service'].apply(keep_first_service)
    flow_synthetic['service'] = flow_synthetic['service'].apply(keep_first_service)
    # weird.log
    try:
        flow_eval_weird = pd.read_csv(os.path.join(args.eval, "weird.log"), header = 8, engine = "python", skipfooter = 1, sep = "\t", names = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "name", "addl", "notice", "peer", "source"])
        flow_ref_weird = pd.read_csv(os.path.join(args.reference, "weird.log"), header = 8, engine = "python", skipfooter = 1, sep = "\t", names = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "name", "addl", "notice", "peer", "source"])
        flow_synthetic_weird = pd.read_csv(os.path.join(args.synthetic, "weird.log"), header = 8, engine = "python", skipfooter = 1, sep = "\t", names = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "name", "addl", "notice", "peer", "source"])
        # elif args.baseline_train:
            # flow_synthetic_weird = pd.read_csv(os.path.join(args.baseline_train, "weird.log"), header = 8, engine = "python", skipfooter = 1, sep = "\t", names = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "name", "addl", "notice", "peer", "source"])
    except Exception as e:
        print(f"Cannot process weird.log!",e)
        exit(1)

    # data.pcap
    try:
        # evaluate with the first 10 MB (due to scalability issue)
        max_index = 10_000_000
        with open(os.path.join(args.eval, "data.pcap"), "rb") as file:
            pcap_eval = file.read(max_index)
        with open(os.path.join(args.reference, "data.pcap"), "rb") as file:
            pcap_ref = file.read(max_index)
        with open(os.path.join(args.synthetic, "data.pcap"), "rb") as file:
            pcap_synthetic = file.read(max_index)
    except Exception as e:
        print(f"Cannot process data.pcap!",e)
        exit(1)

    # ip.csv
    try:
        flow_eval_ip = pd.read_csv(os.path.join(args.eval, "ip.csv"))
        flow_ref_ip = pd.read_csv(os.path.join(args.reference, "ip.csv"))
        flow_synthetic_ip = pd.read_csv(os.path.join(args.synthetic, "ip.csv"))
        # elif args.baseline_train:
            # flow_synthetic_ip = pd.read_csv(os.path.join(args.baseline_train, "ip.csv"))
    except Exception as e:
        print(f"Cannot process ip.csv!",e)
        exit(1)

    # tcp.csv
    try:
        flow_eval_tcp = pd.read_csv(os.path.join(args.eval, "tcp.csv"))
        flow_ref_tcp = pd.read_csv(os.path.join(args.reference, "tcp.csv"))
        flow_synthetic_tcp = pd.read_csv(os.path.join(args.synthetic, "tcp.csv"))
        # elif args.baseline_train:
            # flow_synthetic_tcp = pd.read_csv(os.path.join(args.baseline_train, "tcp.csv"))
    except Exception as e:
        print(f"Cannot process tcp.csv!",e)
        exit(1)


    print("Preprocessing")
    # preprocessing
    for feature in ["id.orig_h", "id.resp_h"]:
        flow_eval[feature] = flow_eval[feature].apply(merge_internet)
        flow_ref[feature] = flow_ref[feature].apply(merge_internet)
        flow_synthetic[feature] = flow_synthetic[feature].apply(merge_internet)

    for feature in ["ip.src", "ip.dst"]:
        flow_eval_ip[feature] = flow_eval_ip[feature].apply(merge_internet)
        flow_ref_ip[feature] = flow_ref_ip[feature].apply(merge_internet)
        flow_synthetic_ip[feature] = flow_synthetic_ip[feature].apply(merge_internet)

    flow_eval["ts"] = flow_eval["ts"].apply(get_time)
    flow_ref["ts"] = flow_ref["ts"].apply(get_time)
    flow_synthetic["ts"] = flow_synthetic["ts"].apply(get_time)

    for feature in ["duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"]:
        flow_eval[feature] = flow_eval[feature].replace("-", "0")
        flow_ref[feature] = flow_ref[feature].replace("-", "0")
        flow_synthetic[feature] = flow_synthetic[feature].replace("-", "0")
        flow_eval[feature] = pd.to_numeric(flow_eval[feature])
        flow_ref[feature] = pd.to_numeric(flow_ref[feature])
        flow_synthetic[feature] = pd.to_numeric(flow_synthetic[feature])
        flow_eval[feature] = np.log10(flow_eval[feature].clip(lower=1e-3))
        flow_ref[feature] = np.log10(flow_ref[feature].clip(lower=1e-3))
        flow_synthetic[feature] = np.log10(flow_synthetic[feature].clip(lower=1e-3))

    for feature in ["ts"]:
        flow_eval[feature] = flow_eval[feature].replace("-", "0")
        flow_ref[feature] = flow_ref[feature].replace("-", "0")
        flow_synthetic[feature] = flow_synthetic[feature].replace("-", "0")
        flow_eval[feature] = pd.to_numeric(flow_eval[feature])
        flow_ref[feature] = pd.to_numeric(flow_ref[feature])
        flow_synthetic[feature] = pd.to_numeric(flow_synthetic[feature])

    for feature in ["orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts", "ts", "duration"]:
        plt.hist(flow_ref[feature].values.tolist(), 50, density=True, alpha=0.75, label="Reference")
        plt.hist(flow_synthetic[feature].values.tolist(), 50, density=True, alpha=0.75, label="Synthetic")
        plt.xlabel(feature)
        plt.ylabel('Probability')
        plt.title(f'Marginal distribution of {feature} for {os.path.split(args.synthetic)[-1]}')
        # plt.text(60, .025, r'$\mu=100,\ \sigma=15$')
        # plt.axis([40, 160, 0, 0.03])
        plt.grid(True)
        plt.legend()
        plt.savefig(os.path.join(args.output,f"marginal-{feature}-{os.path.split(args.synthetic)[-1]}.png"), dpi=300, bbox_inches="tight")
        plt.clf()

    # if args.baseline:
    #     print("Generating new data with",args.baseline)
    #     assert args.baseline_train # TODO proprement
    #     if args.baseline == "naive":
    #         for c in flow_synthetic.columns:
    #             flow_synthetic[c] = flow_synthetic[c].sample(frac=1, random_state=0).reset_index(drop=True)
    #     elif args.baseline == "ros":
    #         # flow_synthetic = flow_synthetic.sample(frac=1, replace=True, random_state=0, axis="index")
    #         flow_synthetic = flow_synthetic.sample(frac=1, replace=True, random_state=0, axis="index")
    #         # use the dataset once with label 0 and twice with label 1. To balance the dataset, ROS will generate as many examples as the dataset

    print(f"\tSYNTHETIC DATA ({args.synthetic_name})")
    results_synthetic = evaluate_flow(flow_eval, flow_synthetic)
    results_synthetic = results_synthetic + evaluate_weird(flow_eval, flow_synthetic, flow_eval_weird, flow_synthetic_weird)
    results_synthetic = results_synthetic + evaluate_pcap(pcap_eval, pcap_synthetic)
    results_synthetic = results_synthetic + evaluate_ip(flow_eval_ip, flow_synthetic_ip)
    results_synthetic = results_synthetic + evaluate_tcp(flow_eval_tcp, flow_synthetic_tcp)

    print("\tREFERENCE DATA")
    results_ref = evaluate_flow(flow_eval, flow_ref)
    results_ref = results_ref + evaluate_weird(flow_eval, flow_ref, flow_eval_weird, flow_ref_weird)
    results_ref = results_ref + evaluate_pcap(pcap_eval, pcap_ref)
    results_ref = results_ref + evaluate_ip(flow_eval_ip, flow_ref_ip)
    results_ref = results_ref + evaluate_tcp(flow_eval_tcp, flow_ref_tcp)

    results_synthetic = { "method": args.synthetic_name, "results": {f"{r['feature']} {r['data']} {r['metric']}": r for r in results_synthetic }}
    results_ref = { "method": "Reference", "results": {f"{r['feature']} {r['data']} {r['metric']}": r for r in results_ref }}
    # results_ref  = { "method": "Reference", "results": results_ref }

    out_file = open(os.path.join(args.output, f"results-{os.path.split(args.synthetic)[-1]}.json"), "w")
    json.dump(results_synthetic, out_file, indent=1)
    out_file = open(os.path.join(args.output, f"results-{os.path.split(args.eval)[-1]}.json"), "w")
    json.dump(results_ref, out_file, indent=1)

    for feature in ["duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"]:
        scaler = StandardScaler()
        scaler.fit(flow_eval[feature].to_frame())
        flow_eval[feature] = scaler.transform(flow_eval[feature].to_frame())
        flow_ref[feature] = scaler.transform(flow_ref[feature].to_frame())
        flow_synthetic[feature] = scaler.transform(flow_synthetic[feature].to_frame())

    pca = PCA(n_components=2)
    pca_eval = pca.fit_transform(flow_eval[["duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"]])
    pca_ref = pca.transform(flow_ref[["duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"]])
    pca_synthetic = pca.transform(flow_synthetic[["duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"]])

    plt.scatter(pca_eval[:,0], pca_eval[:,1], alpha=0.2, label="Evaluation data")
    plt.scatter(pca_ref[:,0], pca_ref[:,1], alpha=0.2, label="Reference data")
    plt.scatter(pca_synthetic[:,0], pca_synthetic[:,1], alpha=0.2, label="Synthetic data")
    plt.xlabel("Principal Component 1")
    plt.ylabel("Principal Component 2")
    plt.grid()
    plt.legend()
    coeff = pca.components_
    labels = ["duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"]
    # Adapted from rom https://stackoverflow.com/questions/47370795/pca-on-sklearn-how-to-interpret-pca-components
    n = coeff.shape[1]
    for i in range(n):
        plt.arrow(0, 0, 5*coeff[0,i], 5*coeff[1,i],color = 'r',alpha = 0.5)
        plt.text(5*coeff[0,i]* 1.15, 5*coeff[1,i] * 1.15, labels[i], color = 'black', ha = 'center', va = 'center')

    plt.savefig(os.path.join(args.output,f"pca-{os.path.split(args.synthetic)[-1]}.png"), dpi=300, bbox_inches="tight")
    plt.clf()
