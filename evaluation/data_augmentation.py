#!/usr/bin/env python3

import os
import argparse
import pandas as pd
from imblearn.over_sampling import SMOTENC
from imblearn.over_sampling import RandomOverSampler
from imblearn.under_sampling import ClusterCentroids
from imblearn.under_sampling import RandomUnderSampler

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Perform data augmentation with baselines."
    )
    parser.add_argument(
        "--train", required=True, help="Select the folder with Zeek logs of train data."
    )
    parser.add_argument("--output", required=True, help="Output directory.")
    parser.add_argument(
        "--method",
        choices=["indhist", "ros", "rus-smote"],
        help="Select a method",
        nargs="+",
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

    for m in args.method:
        print("Generating new data with", m)
        if m == "indhist":
            for c in flow.columns:
                flow[c] = (
                    flow[c]
                    .sample(frac=1, random_state=42, replace=True)
                    .reset_index(drop=True)
                )
        elif m == "ros":
            sm = RandomOverSampler(random_state=42)
            flow, _ = sm.fit_resample(flow, flow["service"])
        # elif m == "cc-smote":
        #     print("Before CC:",len(flow))
        #     cc = ClusterCentroids(random_state=42)
        #     X_resampled, y_resampled = cc.fit_resample(flow, flow["service"])
        #     print("After CC:",len(X_resampled))

        #     # SMOTENC is for nominal and continuous variables
        #     sm = SMOTENC(
        #         categorical_features=[
        #             "id.orig_h",
        #             "id.resp_h",
        #             "id.resp_p",
        #             "proto",
        #             "service",
        #             "history",
        #             "conn_state",
        #             "ip_proto",
        #             "local_orig",
        #             "local_resp",
        #         ],
        #         random_state=42,
        #     )
        #     # flow, _ = sm.fit_resample(flow, flow["service"])
        #     flow, _ = sm.fit_resample(X_resampled, y_resampled)

        elif m == "rus-smote":
            print("Before RUS:", len(flow))
            rus = RandomUnderSampler(sampling_strategy="majority", random_state=42)
            X_resampled, y_resampled = rus.fit_resample(flow, flow["service"])
            print("After RUS:", len(X_resampled))

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
            flow, _ = sm.fit_resample(X_resampled, y_resampled)
            print("After SMOTE:", len(flow))

        flow.to_csv(os.path.join(args.output, m + "-da.csv"), index=False)
