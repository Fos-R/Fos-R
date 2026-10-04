#!/usr/bin/env python3

import pandas as pd
import argparse
import pyod
from pyod.models.iforest import IForest
from pyod.models.ecod import ECOD
from pyod.models.knn import KNN
from pyod.models.lof import LOF
from pyod.models.copod import COPOD
import os
from sklearn.metrics import roc_auc_score
from sklearn.preprocessing import LabelEncoder
from sklearn.preprocessing import StandardScaler


def merge_other(v, known):
    if v in known:
        return v
    else:
        return "other"


def load_data(path):
    file_ext = os.path.splitext(path)[1]
    if file_ext == ".csv":
        return pd.read_csv(path)
    else:
        return pd.read_csv(
            path,
            header=8,
            engine="python",
            skipfooter=1,
            sep="\t",
            names=[
                "ts",
                "uid",
                "id.orig_h",
                "id.orig_p",
                "id.resp_h",
                "id.resp_p",
                "proto",
                "service",
                "duration",
                "orig_bytes",
                "resp_bytes",
                "conn_state",
                "local_orig",
                "local_resp",
                "missed_bytes",
                "history",
                "orig_pkts",
                "orig_ip_bytes",
                "resp_pkts",
                "resp_ip_bytes",
                "tunnel_parents",
                "ip_proto",
            ],
        )


def evaluate(clf, flow_test):
    y_test = clf.decision_function(flow_test.loc[:, flow_test.columns != "label"])
    return roc_auc_score(flow_test["label"], y_test)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Anomaly detection for evaluating data augmentation methods."
    )
    parser.add_argument(
        "--synthetic-data",
        required=True,
        help="Synthetic data used for data augmentation.",
    )
    parser.add_argument("--train-set", required=True, help="Train set file.")
    parser.add_argument("--test-set", required=True, help="Test set file.")
    parser.add_argument("--labels", required=True, help="Labels of the test set.")
    args = parser.parse_args()

    # test_input = args.test_set
    # labels = args.labels
    # test_input = "../data/cupid/cupid-data-augmentation/conn.log"
    # labels = "../data/cupid/cupid-data-augmentation/labels.csv"
    flow_test = load_data(args.test_set)

    flow_labels = pd.read_csv(args.labels)
    flow_test = flow_test.join(flow_labels.set_index("uid"), on="uid", rsuffix="_")
    flow_test = flow_test.dropna()

    flow_test = flow_test.drop(columns=["ts", "uid", "tunnel_parents"], errors="ignore")

    # train_input = "../data/cupid/cupid-train/conn.log"
    flow_train = load_data(args.train_set)
    flow_train = flow_train.drop(
        columns=["ts", "uid", "tunnel_parents"], errors="ignore"
    )

    # synthetic_input = "../data/cupid/cupid-data-augmentation/ros-da.csv"
    flow_synthetic = load_data(args.synthetic_data)
    flow_synthetic = flow_synthetic.drop(
        columns=["ts", "uid", "tunnel_parents"], errors="ignore"
    )

    for feature in ["duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"]:
        flow_train[feature] = flow_train[feature].replace("-", "0")
        flow_test[feature] = flow_test[feature].replace("-", "0")
        flow_synthetic[feature] = flow_synthetic[feature].replace("-", "0")

    for feature in [
        "id.orig_h",
        "id.resp_h",
        "id.resp_p",
        "proto",
        "service",
        "history",
        "conn_state",
        "local_orig",
        "local_resp",
    ]:
        known = list(set(flow_train[feature]))
        le = LabelEncoder().fit(known + ["other"])

        flow_train[feature] = le.transform(flow_train[feature])
        flow_test[feature] = flow_test[feature].apply(merge_other, known=known)
        flow_test[feature] = le.transform(flow_test[feature])
        flow_synthetic[feature] = flow_synthetic[feature].apply(
            merge_other, known=known
        )
        flow_synthetic[feature] = le.transform(flow_synthetic[feature])

    for feature in ["duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"]:
        scaler = StandardScaler()
        scaler.fit(flow_train[feature].to_frame())
        flow_train[feature] = scaler.transform(flow_train[feature].to_frame())
        flow_test[feature] = scaler.transform(flow_test[feature].to_frame())
        flow_synthetic[feature] = scaler.transform(flow_synthetic[feature].to_frame())

    for clf in [
        IForest(random_state=42, n_jobs=20),
        # ECOD(n_jobs=20),
        KNN(n_jobs=20),
        LOF(n_jobs=20),
        # COPOD(),
    ]:
        print(clf.__class__.__name__)
        clf.fit(flow_train)

        roc = evaluate(clf, flow_test)
        print("ROC (train):", roc)

        # clf.fit(pd.concat([flow_train, flow_synthetic]))
        # roc = evaluate(clf, flow_test)
        # print("ROC (train+DA):", roc)

        clf.fit(flow_synthetic)
        roc = evaluate(clf, flow_test)
        print("ROC (DA):", roc)
