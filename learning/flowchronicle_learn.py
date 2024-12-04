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

def describe_bn(bn):
    topo_order = []
    roots = []
    bn.fit() # compute probabilities and not just counts # TODO: do automatically after search

    # Compute the topological order so generation is easier
    for node in bn.bn.nodes:
        if len(bn.bn.get_parents(node)) == 0:
            roots.append(node)

    while len(roots) > 0:
        n = roots.pop()
        topo_order.append(n)
        for node in bn.bn.nodes:
            if n in bn.bn.get_parents(node):
                for p in bn.bn.get_parents(node):
                    if p not in topo_order:
                        break
                else:
                    roots.append(node)
    assert len(topo_order) == len(bn.bn.nodes)

    graph = []
    node_number = {}
    for i, node in enumerate(topo_order): # order should be topological!
        node_number[node] = i
        d = {}
        d["feature_number"] = bn.col_number_map[node]
        d["partial_flow_number"] = bn.row_number_map[node]
        d["parents"] = [node_number[p] for p in bn.bn.get_parents(node)] # get index of parents
        out_cpt = []
        cpd = bn.bn.get_cpds(node)
        evidence = cpd.variables[1:]
        evidence_card = cpd.cardinality[1:]
        headers_list = []
        if evidence:
            col_indexes = np.array(list(product(*[range(j) for j in evidence_card])))
            for j in range(len(evidence_card)):
                column_header = [cpd.state_names[evidence[j]][d] for d in col_indexes.T[j]]
                headers_list.append(column_header)
            for j,l in enumerate(cpd.get_values().transpose()):
                cpt_line = { "parents_values": [int(headers_list[k][j]) for k in range(len(evidence))], "probas": list(zip([int(v) for v in cpd.state_names[cpd.variable]], l.tolist())) }
                out_cpt.append(cpt_line)
            d["cpt"] = out_cpt
        else: # no parents
            probas = [(int(cpd.state_names[cpd.variable][j]), float(cpd.get_values()[j][0])) for j in range(cpd.variable_card)]
            d["cpt"] = [{ "parents_values": [], "probas": probas}]
        graph.append(d)
    return {"graph": graph}

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

    m = search.search(dataset, iter_max=2, load_checkpoint=0, model_name=f'test')

    t2 = time.time()
    dif2 = divmod(t2-t1,3600)
    print("Learning time: {} hours, {} minutes and {} seconds".format(dif2[0], *divmod(dif2[1],60)))

    c = m.cover
    cover_stats = c.get_cover_stats()
    patterns_usage = cover_stats.get_pattern_usage()
    metadata = {}
    metadata["creation_time"] = str(datetime.datetime.now())
    metadata["input_file"] = os.path.split(args.input)[-1]
    patterns = []

    weights = []

    for p in m.pattern_set:
        d = {}
        partial_flows = []
        for row,pf in enumerate(p.pattern):
            current_pf = [{"type": "Free"}]*(len(df.columns)-1) # timestamp is handled separately
            placeholders = {}
            for k,v in pf.pattern.items():
                if v.attr_type == attribute_value.AttributeType.FIX:
                    current_pf[k] = { "type": "Fixed", "value": v.value }
                elif v.attr_type == attribute_value.AttributeType.USE_PLACEHOLDER:
                    (r,c) = placeholders[v.value]
                    current_pf[k] = { "type": "ReuseVariable", "col": c, "row": r }
                elif v.attr_type == attribute_value.AttributeType.SET_PLACEHOLDER:
                    placeholders[v.value] = (row,k)

            partial_flows.append(current_pf)
        d["start_ts_distrib"] = 0 # TODO
        d["partial_flows"] = partial_flows
        d["bayesian_network"] = describe_bn(p.bn)
        assert len(partial_flows)*(len(df.columns)-1) - len(pf.pattern) == len([k for pf in partial_flows for k in pf if k.get("type")=="Free"]) # check there is the correct number of "Free" cells
        patterns.append(d)
        weights.append(patterns_usage[p])

    weights.append(m.cover.get_empty_pattern_usage())
    tmp = {}
    tmp["default_pattern"] = describe_bn(m.get_base_bn())
    tmp["weights"] = weights
    tmp["metadata"] = metadata
    tmp["patterns"] = patterns
    try:
        out_file = open(args.output, "w")
        json.dump(tmp, out_file, indent=4)
        print("JSON file successfully created")
    except Exception as e:
        print("Error during json save:",e)

