import os
import argparse
import time
import logging
import pandas as pd
import datetime
from bidict import bidict
import json
import numpy as np
from itertools import product

import flowchronicle.dataloader as dl
from flowchronicle import search
from flowchronicle import attribute_value

def discretize(df, n_components_range=[1,100], optimize=False, transform_timestamps=True, v2=True): # TODO: vérifier si utiliser v1 (GMM) ou v2 (bins)

    data = df.copy()

    continuous = data.loc[:,["In Byte", "Out Byte", "In Packet", "Out Packet", "Duration"]]
    dic = {}
    for col in continuous.columns:
        if not v2:
            m = continuous[col].describe([.9])[5]
            temp = continuous.loc[data[col]<=m, col].to_numpy().reshape(-1,1)
            if optimize:
                best_model, best_params = optimize_gmm(temp, n_components_range)
                print(f"For {col}, the best parameters of the GMM are : ", best_params)
                best_n_components = best_params["n_components"]
            else :
                if col == "In Byte":
                    best_n_components = 42
                    best_model = GaussianMixture(n_components=best_n_components, covariance_type='diag', random_state=42).fit(temp)
                if col == "Out Byte":
                    best_n_components = 43
                    best_model = GaussianMixture(n_components=best_n_components, covariance_type='diag', random_state=42).fit(temp)
                if col == "In Packet":
                    best_n_components = 41
                    best_model = GaussianMixture(n_components=best_n_components, covariance_type='tied', random_state=42).fit(temp)
                if col == "Out Packet":
                    best_n_components = 40
                    best_model = GaussianMixture(n_components=best_n_components, covariance_type='tied', random_state=42).fit(temp)
                if col == "Duration":
                    best_n_components = 40
                    best_model = GaussianMixture(n_components=best_n_components, covariance_type='spherical', random_state=42).fit(temp)
            dic[col] = {"edge":m, "max": continuous[col].max(), "weights": best_model.weights_.squeeze(), "n_components": best_n_components, "means": best_model.means_.squeeze(), "std": best_model.covariances_.squeeze()}
            continuous.loc[data[col]<=m, col] = best_model.predict(temp)
            continuous.loc[data[col]>m, col] = best_n_components
            data[col] = continuous[col]
        else:
            c = continuous[col]
            j = c.copy()
            c = c[c!=0]
            c = pd.qcut(c, 5, duplicates="drop") # FIXME avant c’était 40
            j.loc[j!=0] = c
            d = bidict(zip(list(range(1,c.nunique()+1)), c.cat.categories))
            d[0] = 0
            j = j.replace(d.inverse).astype(int)
            data[col] = j
            dic[col] = d
    if transform_timestamps:
        data['Date first seen'] = time_to_int(df['Date first seen'], 100)

    return data, dic


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Train and generate synthetic network traffic.')
    parser.add_argument('--output', required=True, help='Path to the output file.')
    parser.add_argument('--input', required=True, help='Path to the input pcap file.')

    logging.basicConfig(level=logging.ERROR)
    logger = logging.getLogger("pgmpy")
    logger.setLevel(logging.ERROR)

    args = parser.parse_args()

    t0 = time.time()

    df = pd.read_csv(args.input)

    df.drop(columns=['time_sequence','payloads'], inplace=True)
    # df['timestamp'] = pd.to_datetime(df['timestamp'], unit="s", origin="unix") # TODO: devrait tout garder en epoch unix si possible…
    df.rename(columns={"timestamp": "Date first seen", "duration": "Duration","protocol": "Proto", "src_ip": "Src IP Addr", "dst_ip": "Dst IP Addr", "dst_port": "Dst Pt", "fwd_packets": "In Packet", "bwd_packets": "Out Packet", "fwd_bytes": "In Byte","bwd_bytes": "Out Byte"}, inplace=True) # TODO: vérifier in=bwd, out=fwd

    df['Date first seen'] = (df['Date first seen']*1000).astype(int) # use a ms precision
    df['Duration'] = (df['Duration']*1000).astype(int) # use a ms precision
    df['Dst Pt'] = df['Dst Pt'].astype(int)
    df['In Byte'] = df['In Byte'].astype(int)
    df['In Packet'] = df['In Packet'].astype(int)
    df['Out Byte'] = df['Out Byte'].astype(int)
    df['Out Packet'] = df['Out Packet'].astype(int)

    df = df.sort_values("Date first seen")
    df.reset_index(inplace=True, drop=True)
    train = df

    train_d, discrete_dic = discretize(train, transform_timestamps = False)
    #We need to transform the timestamps separately from the rest so the continuous representation will keep the initial timestamps
    dataset = dl.Dataset(train_d.copy())

    cont_rept = dl.ContinousRepr()
    df = train.copy()
    cont_rept.add_first_flow_time(df['Date first seen'].iloc[0])
    cont_rept.add_time_precision(100)
    # in bytes cut points
    cont_rept.add_cutpoints(discrete_dic)
    dataset.cont_repr = cont_rept

    t1 = time.time()
    dif1 = divmod(t1-t0,3600)
    print("Preprocessing time: {} hours, {} minutes and {} seconds".format(dif1[0], *divmod(dif1[1],60)))

    m = search.search(dataset, load_checkpoint=0, model_name=f'test')

    t2 = time.time()
    dif2 = divmod(t2-t1,3600)
    print("Learning time: {} hours, {} minutes and {} seconds".format(dif2[0], *divmod(dif2[1],60)))

    m.save_model(args.output+".tmp")


