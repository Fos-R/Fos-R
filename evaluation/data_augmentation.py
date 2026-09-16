#!/usr/bin/env python3

import os
import argparse
import pandas as pd
from imblearn.over_sampling import SMOTENC
from imblearn.over_sampling import RandomOverSampler

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Perform data augmentation with baselines."
    )
    parser.add_argument(
        "--train", required=True, help="Select the folder with Zeek logs of train data."
    )
    parser.add_argument("--output", required=True, help="Output directory.")
    # TODO: renommer naive
    parser.add_argument(
        "--method", choices=["naive", "ros", "smote", "adasyn"], help="Select a method"
    )
    args = parser.parse_args()

    try:
        os.mkdir(args.output)
    except FileExistsError:
        pass
    except Exception as e:
        print(f"An error occurred: {e}")
        exit()

    # normalize the paths
    args.train = os.path.normpath(args.train)

    print("Loading data")
    # conn.log
    try:
        flow = pd.read_csv(
            os.path.join(args.train, "conn.log"),
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
    except Exception as e:
        print(f"Cannot process conn.log!", e)
        exit(1)

    flow = flow.drop(columns=["ts", "uid", "tunnel_parents"])
    for feature in ["duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"]:
        flow[feature] = flow[feature].replace("-", "0")

    print("Generating new data with", args.method)
    if args.method == "naive":
        for c in flow.columns:
            flow[c] = flow[c].sample(frac=1, random_state=0).reset_index(drop=True)
    elif args.method == "ros":
        sm = RandomOverSampler(random_state=42)
        flow, _ = sm.fit_resample(flow, flow["service"])
    elif args.method == "smote":
        # SMOTENC is for nominal and continuous variables
        sm = SMOTENC(
            categorical_features=[
                "id.orig_h",
                "id.resp_h",
                "id.resp_p",
                "proto",
                "service",
                "history",
                "conn_state",
                "ip_proto",
                "local_orig",
                "local_resp",
            ],
            random_state=42,
        )
        flow, _ = sm.fit_resample(flow, flow["service"])

    flow.to_csv(os.path.join(args.output, args.method + "-da.csv"), index=False)
