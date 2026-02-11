import os
import argparse
import pandas as pd
import numpy as np
from math import log2
from scipy.stats import wasserstein_distance
# from sklearn.ensemble import IsolationForest
from isotree import IsolationForest
from sklearn.preprocessing import LabelEncoder
from imblearn.over_sampling import RandomOverSampler
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.ensemble import RandomForestClassifier
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.manifold import TSNE
from sklearn.metrics.pairwise import cosine_similarity
from scipy.spatial.distance import hamming
import bleu
import rouge
from vendi_score import vendi

pd.options.mode.copy_on_write = True

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
    results = {}

    results["Pkt TCP flags"] = jsd(flow_real["tcp.flags"],flow_synthetic["tcp.flags"])

    return results


def evaluate_ip(flow_real, flow_synthetic):
    results = {}

    results["Pkt TTL"] = jsd(flow_real["ip.ttl"],flow_synthetic["ip.ttl"])
    results["Pkt Source IP"] = jsd(flow_real["ip.src"],flow_synthetic["ip.src"])
    results["Pkt Dest. IP"] = jsd(flow_real["ip.dst"],flow_synthetic["ip.dst"])
    results["Pkt Protocol"] = jsd(flow_real["ip.proto"],flow_synthetic["ip.proto"])
    results["Pkt Length"] = wasserstein_distance(flow_real["ip.len"],flow_synthetic["ip.len"])
    return results

def evaluate(flow_real, flow_synthetic, pcap_real, pcap_synthetic):
    results = {}

    # JSD for categorical data
    # print(f"Connection state:\n\tReal: {flow_real['conn_state'].value_counts(normalize=True)}\n\tSynthetic: {flow_synthetic['conn_state'].value_counts(normalize=True)}")

    results["Flow Source IP"] = jsd(flow_real["id.orig_h"],flow_synthetic["id.orig_h"])
    results["Flow Dest. IP"] = jsd(flow_real["id.resp_h"],flow_synthetic["id.resp_h"])
    results["Flow Dest. port"] = jsd(flow_real["id.resp_p"],flow_synthetic["id.resp_p"])
    results["Flow Protocol"] = jsd(flow_real["proto"],flow_synthetic["proto"])
    results["Flow Service"] = jsd(flow_real["service"],flow_synthetic["service"])
    results["Flow History"] = jsd(flow_real["history"],flow_synthetic["history"])
    # we only consider connections with a connection state (i.e., TCP)
    results["Flow Connection state"] = jsd(flow_real[flow_real["conn_state"] != "-"]["conn_state"],flow_synthetic[flow_synthetic["conn_state"] != "-"]["conn_state"])
    results["Flow IP protocol"] = jsd(flow_real["ip_proto"],flow_synthetic["ip_proto"])

    # EMD for numerical data
    results["Flow Duration"] = wasserstein_distance(flow_real["duration"],flow_synthetic["duration"])
    results["Flow Source bytes"] = wasserstein_distance(flow_real["orig_bytes"],flow_synthetic["orig_bytes"])
    results["Flow Dest. bytes"] = wasserstein_distance(flow_real["resp_bytes"],flow_synthetic["resp_bytes"])
    results["Flow Source packets"] = wasserstein_distance(flow_real["orig_pkts"],flow_synthetic["orig_pkts"])
    results["Flow Dest. packets"] = wasserstein_distance(flow_real["resp_pkts"],flow_synthetic["resp_pkts"])
    results["Flow Time"] = wasserstein_distance(flow_real["ts"],flow_synthetic["ts"])

    features_if = ["id.orig_h", "id.resp_h", "id.resp_p", "proto", "service", "history", "conn_state", "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"]
    flow_real_if = flow_real[features_if]
    flow_synthetic_if = flow_synthetic[features_if]

    for feature in ["id.orig_h", "id.resp_h", "id.resp_p", "proto", "service", "history", "conn_state"]:
        le = LabelEncoder().fit(list(flow_real_if[feature])+list(flow_synthetic_if[feature]))
        flow_real_if[feature] = le.transform(flow_real_if[feature])
        flow_synthetic_if[feature] = le.transform(flow_synthetic_if[feature])
        flow_real_if[feature] = flow_real_if[feature].astype("category") # for IF
        flow_synthetic_if[feature] = flow_synthetic_if[feature].astype("category") # for IF

    discrete_similarity = lambda l1, l2: 1-hamming(l1,l2)
    # use only 1000 flows chosen randomly
    discrete_samples_real = flow_real[["id.orig_h", "id.resp_h", "id.resp_p", "proto", "service","history", "conn_state", "ip_proto"]].sample(n=1000, random_state=0).values.tolist()
    discrete_samples_synthetic = flow_synthetic[["id.orig_h", "id.resp_h", "id.resp_p", "proto", "service","history", "conn_state", "ip_proto"]].sample(n=1000, random_state=0).values.tolist()

    # Vendi describes a dataset and is not a distance.
    results["Discrete Vendi"] = vendi.score(discrete_samples_synthetic, discrete_similarity) / len(discrete_samples_synthetic) - vendi.score(discrete_samples_real, discrete_similarity) / len(discrete_samples_real)

    continuous_samples_real = flow_real[["duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts", "ts"]].sample(n=1000, random_state=0).values.tolist()
    continuous_samples_synthetic = flow_synthetic[["duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts", "ts"]].sample(n=1000, random_state=0).values.tolist()

    # TODO: vérifier
    results["Continuous Vendi"] = vendi.score_dual(cosine_similarity(continuous_samples_synthetic)) / len(discrete_samples_synthetic) - vendi.score_dual(cosine_similarity(continuous_samples_real)) / len(discrete_samples_real)

    results["BLEU"] = bleu.compute_bleu(translation_corpus=[list(pcap_synthetic)], reference_corpus=[[list(pcap_real)]], max_order=4)[0]
    results["ROUGE"] = rouge.rouge_n(evaluated_sentences=list(pcap_synthetic), reference_sentences=list(pcap_eval), n=4)[0]
    results["Bytes JSD"] = jsd(list(pcap_real), list(pcap_synthetic))



# isotree peut traiter les variables catégoriques : https://github.com/david-cortes/isotree

    # TODO: preprocessing id.resp_p pour réduire la cardinalité qui risque de coincer IF

    # print(len(flow_real_if), len(flow_synthetic_if))
    # flow_synthetic_if = flow_synthetic_if.sample(n=len(flow_real_if), random_state=0)
    # print(len(flow_real_if), len(flow_synthetic_if))
    # flow_real_if = flow_real_if.drop_duplicates()
    # flow_synthetic_if = flow_synthetic_if.drop_duplicates() # TODO: à virer ?

    # # flow_synthetic_if = flow_synthetic_if.sample(n=40, random_state=0)
    # # flow_real_if = flow_real_if.sample(n=40, random_state=0)

    # print(flow_real_if.dtypes)
    # # Is the synthetic included in the real data? i.e., realism
    # clf = IsolationForest(random_state=0).fit(flow_real_if)
    # print(sum(clf.predict(flow_synthetic_if)))
    # anomalies = clf.predict(flow_synthetic_if)
    # # anomalies = [1 if s == -1 else 0 for s in clf.predict(flow_synthetic_if)]
    # print(1-sum(anomalies)/len(anomalies))
    # results["Realism"] = 1-sum(anomalies)/len(anomalies)

    # # Is the real included in the synthetic data? i.e., diversity
    # # clf = IsolationForest(random_state=0, n_estimators=10000).fit(flow_synthetic_if)
    # # anomalies = [1 if s == -1 else 0 for s in clf.predict(flow_real_if)]
    # # results["Diversity"] = 1-sum(anomalies)/len(anomalies)
    # results["Diversity"] = 0


# version avec scikit-learn
    # # Is the synthetic included in the real data? i.e., realism
    # clf = IsolationForest(random_state=0, n_estimators=10000).fit(flow_real_if)
    # print(sum(clf.predict(flow_synthetic_if)))
    # anomalies = [1 if s == -1 else 0 for s in clf.predict(flow_synthetic_if)]
    # print(1-sum(anomalies)/len(anomalies))
    # results["Realism"] = 1-sum(anomalies)/len(anomalies)

    # # Is the real included in the synthetic data? i.e., diversity
    # clf = IsolationForest(random_state=0, n_estimators=10000).fit(flow_synthetic_if)
    # anomalies = [1 if s == -1 else 0 for s in clf.predict(flow_real_if)]
    # results["Diversity"] = 1-sum(anomalies)/len(anomalies)

    return results

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Learn a time profile for Fos-R.')
    parser.add_argument('--eval', required=True, help="Select the folder with Zeek logs of evaluation data.")
    parser.add_argument('--reference', required=True, help="Select the folder with Zeek logs of reference data.")
    parser.add_argument('--synthetic', help="Select the folder with Zeek logs of synthetic data.")
    parser.add_argument('--baseline', choices=["naive","ros","smote","adasyn"], help="Select a baseline to run")
    parser.add_argument('--baseline-train', help="Select the folder with Zeek logs of train data.")
    args = parser.parse_args()

    print("Loading data")
    # conn.log
    try:
        flow_eval = pd.read_csv(os.path.join(args.eval, "conn.log"), header = 8, engine = "python", skipfooter = 1, sep = "\t", names = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp", "missed_bytes", "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "tunnel_parents", "ip_proto"])
        flow_ref = pd.read_csv(os.path.join(args.reference, "conn.log"), header = 8, engine = "python", skipfooter = 1, sep = "\t", names = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp", "missed_bytes", "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "tunnel_parents", "ip_proto"])
        if args.synthetic:
            flow_synthetic = pd.read_csv(os.path.join(args.synthetic, "conn.log"), header = 8, engine = "python", skipfooter = 1, sep = "\t", names = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp", "missed_bytes", "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "tunnel_parents", "ip_proto"])
        elif args.baseline_train:
            flow_synthetic = pd.read_csv(os.path.join(args.baseline_train, "conn.log"), header = 8, engine = "python", skipfooter = 1, sep = "\t", names = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp", "missed_bytes", "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "tunnel_parents", "ip_proto"])
    except Exception as e:
        print(f"Cannot process conn.log!",e)
        exit(1)

    # weird.log
    try:
        flow_eval_weird = pd.read_csv(os.path.join(args.eval, "weird.log"), header = 8, engine = "python", skipfooter = 1, sep = "\t", names = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "name", "addl", "notice", "peer", "source"])
        flow_ref_weird = pd.read_csv(os.path.join(args.reference, "weird.log"), header = 8, engine = "python", skipfooter = 1, sep = "\t", names = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "name", "addl", "notice", "peer", "source"])
        if args.synthetic:
            flow_synthetic_weird = pd.read_csv(os.path.join(args.synthetic, "weird.log"), header = 8, engine = "python", skipfooter = 1, sep = "\t", names = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "name", "addl", "notice", "peer", "source"])
        elif args.baseline_train:
            flow_synthetic_weird = pd.read_csv(os.path.join(args.baseline_train, "weird.log"), header = 8, engine = "python", skipfooter = 1, sep = "\t", names = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "name", "addl", "notice", "peer", "source"])
    except Exception as e:
        print(f"Cannot process weird.log!",e)
        exit(1)

    # data.pcap
    try:
        # evaluate with the first 10 MB (due to scalability issue)
        max_index = 10_000_000
        with open(os.path.join(args.eval, "data.pcap"), "rb") as file:
            pcap_eval = file.read()[:max_index]
        with open(os.path.join(args.reference, "data.pcap"), "rb") as file:
            pcap_ref = file.read()[:max_index]
        with open(os.path.join(args.synthetic, "data.pcap"), "rb") as file:
            pcap_synthetic = file.read()[:max_index]
    except Exception as e:
        print(f"Cannot process data.pcap!",e)
        exit(1)

    if False:
        # ip.csv
        try:
            flow_eval_ip = pd.read_csv(os.path.join(args.eval, "ip.csv"))
            flow_ref_ip = pd.read_csv(os.path.join(args.reference, "ip.csv"))
            if args.synthetic:
                flow_synthetic_ip = pd.read_csv(os.path.join(args.synthetic, "ip.csv"))
            elif args.baseline_train:
                flow_synthetic_ip = pd.read_csv(os.path.join(args.baseline_train, "ip.csv"))
        except Exception as e:
            print(f"Cannot find ip.csv!",e)
            exit(1)

    # tcp.csv
    # try:
    #     flow_eval_tcp = pd.read_csv(os.path.join(args.eval, "tcp.csv"))
    #     flow_ref_tcp = pd.read_csv(os.path.join(args.reference, "tcp.csv"))
    #     if args.synthetic:
    #         flow_synthetic_tcp = pd.read_csv(os.path.join(args.synthetic, "tcp.csv"))
    #     elif args.baseline_train:
    #         flow_synthetic_tcp = pd.read_csv(os.path.join(args.baseline_train, "tcp.csv"))
    # except Exception as e:
    #     print(f"Cannot find tcp.csv!",e)
    #     exit(1)


    # print(f"Name\n\tEval: {flow_eval_weird['name'].value_counts(normalize=True)}\n\tSynthetic: {flow_synthetic_weird['name'].value_counts(normalize=True)}")
    # exit()

    print("Preprocessing")
    # preprocessing
    for feature in ["id.orig_h", "id.resp_h"]:
        flow_eval[feature] = flow_eval[feature].apply(merge_internet)
        flow_ref[feature] = flow_ref[feature].apply(merge_internet)
        flow_synthetic[feature] = flow_synthetic[feature].apply(merge_internet)

    flow_eval["ts"] = flow_eval["ts"].apply(get_time)
    flow_ref["ts"] = flow_ref["ts"].apply(get_time)
    flow_synthetic["ts"] = flow_synthetic["ts"].apply(get_time)

    for feature in ["duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts", "ts"]:
        flow_eval[feature] = flow_eval[feature].replace("-", "0")
        flow_ref[feature] = flow_ref[feature].replace("-", "0")
        flow_synthetic[feature] = flow_synthetic[feature].replace("-", "0")
        flow_eval[feature] = pd.to_numeric(flow_eval[feature])
        flow_ref[feature] = pd.to_numeric(flow_ref[feature])
        flow_synthetic[feature] = pd.to_numeric(flow_synthetic[feature])

    if args.baseline:
        print("Generating new data with",args.baseline)
        assert args.baseline_train # TODO proprement
        if args.baseline == "naive":
            for c in flow_synthetic.columns:
                flow_synthetic[c] = flow_synthetic[c].sample(frac=1, random_state=0).reset_index(drop=True)
        elif args.baseline == "ros":
            # flow_synthetic = flow_synthetic.sample(frac=1, replace=True, random_state=0, axis="index")
            flow_synthetic = flow_synthetic.sample(frac=1, replace=True, random_state=0, axis="index")
            # use the dataset once with label 0 and twice with label 1. To balance the dataset, ROS will generate as many examples as the dataset

# TODO: différencier réel et synthétique avec RF
# TODO: baseline: RB (pyagrum) ?
# TODO: s’assurer du déterminisme
# TODO: s’assurer que les tailles de ref et de synthétique sont similaire ?

    if True:
        print("Evaluating synthetic data")
        results_synthetic = evaluate(flow_eval, flow_synthetic, pcap_eval, pcap_synthetic)
        # results_synthetic = results_synthetic | evaluate_ip(flow_eval_ip, flow_synthetic_ip)
        # results_synthetic = results_synthetic | evaluate_tcp(flow_eval_tcp, flow_synthetic_tcp)

        print("Evaluating reference data")
        results_ref = evaluate(flow_eval, flow_ref, pcap_eval, pcap_ref)
        # results_ref = results_ref | evaluate_ip(flow_eval_ip, flow_ref_ip)
        # results_ref = results_synthetic | evaluate_tcp(flow_eval_tcp, flow_ref_tcp)

        marginal_score = []
        for k in results_synthetic.keys():
        # for k in ["Source IP","Dest. IP","Dest. port","Protocol","Service","History","Connection state","IP protocol","Duration","Source bytes","Dest. bytes","Source packets","Dest. packets","Time"]:
            print(f"{k}:\n\tReference: {results_ref[k]}\n\tSynthetic: {results_synthetic[k]}\n\tScore: {abs(results_synthetic[k] - results_ref[k])}")
            marginal_score.append(abs(results_synthetic[k] - results_ref[k]))
        print(f"Overall mean marginal score: {sum(marginal_score) / len(marginal_score)}")

        # for k in ["Realism","Diversity"]:
        #     print(f"{k}:\n\tReference: {results_ref[k]}\n\tSynthetic: {results_synthetic[k]}")

    # embeddings = TSNE(n_components=2, learning_rate='auto', init='random', perplexity=3, random_state=0).fit_transform(pd.concat([flow_eval[["id.orig_p", "id.resp_p", "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp", "missed_bytes", "history", "orig_pkts", "resp_pkts"]], flow_synthetic[["id.orig_p", "id.resp_p", "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp", "missed_bytes", "history", "orig_pkts", "resp_pkts"]]]), [0]*len(flow_eval)+[1]*len(flow_synthetic))

    # plt.scatter(embeddings[:,0], embeddings[:,1])
    # plt.show()




    print("C2ST evaluation")
    clf = RandomForestClassifier(random_state=0)

    # transform to numeric
    for feature in ["id.orig_p", "id.resp_p", "proto", "service", "history", "conn_state", "local_orig", "local_resp"]:
        le = LabelEncoder().fit(list(flow_eval[feature])+list(flow_synthetic[feature]))
        flow_eval[feature] = le.transform(flow_eval[feature])
        flow_synthetic[feature] = le.transform(flow_synthetic[feature])

    X_train, X_test, y_train, y_test = train_test_split(pd.concat([flow_eval[["id.orig_p", "id.resp_p", "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp", "missed_bytes", "history", "orig_pkts", "resp_pkts"]], flow_synthetic[["id.orig_p", "id.resp_p", "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp", "missed_bytes", "history", "orig_pkts", "resp_pkts"]]]), [0]*len(flow_eval)+[1]*len(flow_synthetic), test_size=0.2, random_state=42)
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)

    print("C2ST between real and synthetic",accuracy_score(y_test, y_pred))
    feature_imp_df = pd.DataFrame({'Feature': X_train.keys(), 'Gini Importance': clf.feature_importances_}).sort_values('Gini Importance', ascending=False)
    print(feature_imp_df)

    # transform to numeric
    for feature in ["id.orig_p", "id.resp_p", "proto", "service", "history", "conn_state", "local_orig", "local_resp"]:
        le = LabelEncoder().fit(list(flow_eval[feature])+list(flow_ref[feature]))
        flow_eval[feature] = le.transform(flow_eval[feature])
        flow_ref[feature] = le.transform(flow_ref[feature])

    X_train, X_test, y_train, y_test = train_test_split(pd.concat([flow_eval[["id.orig_p", "id.resp_p", "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp", "missed_bytes", "history", "orig_pkts", "resp_pkts"]], flow_ref[["id.orig_p", "id.resp_p", "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp", "missed_bytes", "history", "orig_pkts", "resp_pkts"]]]), [0]*len(flow_eval)+[1]*len(flow_ref), test_size=0.2, random_state=42)
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)

    print("C2ST between real and reference",accuracy_score(y_test, y_pred))
    feature_imp_df = pd.DataFrame({'Feature': X_train.keys(), 'Gini Importance': clf.feature_importances_}).sort_values('Gini Importance', ascending=False)
    print(feature_imp_df)


    # for feature in ["duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts", "ts"]:
    #     scaler = StandardScaler()
    #     scaler.fit(flow_eval[feature].to_frame())
    #     flow_eval[feature+"_standard"] = scaler.transform(flow_eval[feature].to_frame())
    #     flow_ref[feature+"_standard"] = scaler.transform(flow_ref[feature].to_frame())
    #     flow_synthetic[feature+"_standard"] = scaler.transform(flow_synthetic[feature].to_frame())

    # pca = PCA(n_components=2)
    # pca_eval = pca.fit_transform(flow_eval[["duration_standard", "orig_bytes_standard", "resp_bytes_standard", "orig_pkts_standard", "resp_pkts_standard", "ts_standard"]])
    # pca_ref = pca.transform(flow_ref[["duration_standard", "orig_bytes_standard", "resp_bytes_standard", "orig_pkts_standard", "resp_pkts_standard", "ts_standard"]])
    # pca_synthetic = pca.transform(flow_synthetic[["duration_standard", "orig_bytes_standard", "resp_bytes_standard", "orig_pkts_standard", "resp_pkts_standard", "ts_standard"]])
    # embeddings = TSNE(n_components=2, learning_rate='auto', init='random', perplexity=3, random_state=0).fit_transform(pd.concat([flow_eval[["id.orig_p", "id.resp_p", "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp", "missed_bytes", "history", "orig_pkts", "resp_pkts"]], flow_synthetic[["id.orig_p", "id.resp_p", "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp", "missed_bytes", "history", "orig_pkts", "resp_pkts"]]]), [0]*len(flow_eval)+[1]*len(flow_synthetic))

    # plt.scatter(embeddings[:,0], embeddings[:,1])
    # plt.show()


    # plt.scatter(pca_eval[:,0], pca_eval[:,1], color="r")
    # plt.scatter(pca_ref[:,0], pca_ref[:,1], color="b")
    # plt.scatter(pca_synthetic[:,0], pca_synthetic[:,1], color="y")
    # plt.show()



# C2ST (distinguer vrai et faux) avec RF: Classifier Two-Sample Tests (C2ST)
# visualisation
# data augmentation (RF) avec pyod
