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
from flowchronicle import model
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
            print(out_cpt)
            d["cpt"] = out_cpt
        else: # no parents
            probas = [(int(cpd.state_names[cpd.variable][j]), float(cpd.get_values()[j][0])) for j in range(cpd.variable_card)]
            d["cpt"] = [{ "parents_values": [], "probas": probas}]
        graph.append(d)

    return graph



if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Train and generate synthetic network traffic.')
    parser.add_argument('--input', required=True, help='Path to the input pcap file.')
    parser.add_argument('--output', required=True, help='Path to the output file.')
    args = parser.parse_args()

    m = model.Model.load_model(args.output+".tmp")

    c = m.cover
    dataset = c.dataset
    cover_stats = c.get_cover_stats()
    patterns_usage = cover_stats.get_pattern_usage()
    metadata = {}
    metadata["creation_time"] = str(datetime.datetime.now())
    metadata["input_file"] = os.path.split(args.input)[-1]
    patterns = []

    weights = []

    feature_rename = {"Dst IP Addr": "DstIP", "Src IP Addr": "SrcIP", "In Packet": "FwdPkt", "Out Packet": "BwdPkt", "In Byte": "FwdByt", "Out Byte": "BwdByt", "Proto": "Proto", "Dst Pt": "DstPt"}

    for p in m.pattern_set:
        d = {}
        partial_flows = []
        print(p.pattern)
        for row,pf in enumerate(p.pattern):
            current_pf = []
            for k,v in pf.pattern.items():
                col = dataset.col_name_map[k]
                # print(k,v)
                # print(dataset.column_value_dict)
                # print(col)
                # print(feature_rename[col])
                if v.attr_type == attribute_value.AttributeType.FIX:
                    val = dataset.column_value_dict[col][v.value]
                    if type(val) == np.int64:
                        val = int(val)
                    current_pf.append({ "type": "Fixed", "feature": { "type": feature_rename[col], "domain": [val] } })
                elif v.attr_type == attribute_value.AttributeType.USE_PLACEHOLDER:
                    (r,c) = placeholders[v.value]
                    print("R,C",r,c)
                    current_pf.append({})
                    # current_pf[k] = { "type": "ReuseVariable", { "col": c, "row": r }
                elif v.attr_type == attribute_value.AttributeType.SET_PLACEHOLDER:
                    placeholders[v.value] = (row,k)

            partial_flows.append(current_pf)
        d["partial_flows"] = partial_flows
        d["bayesian_network"] = describe_bn(p.bn)
        # assert len(partial_flows)*(len(df.columns)-1) - len(pf.pattern) == len([k for pf in partial_flows for k in pf if k.get("type")=="Free"]) # check there is the correct number of "Free" cells
        patterns.append(d)
        weights.append(patterns_usage[p])

    patterns.append({"partial_flows": [{"time_distrib": 0, "row": []}], "bayesian_network": describe_bn(m.get_base_bn())})
    weights.append(m.cover.get_empty_pattern_usage())
    d = {}
    d["pattern_weights"] = weights
    d["metadata"] = metadata
    d["patterns"] = patterns
    try:
        out_file = open(args.output, "w")
        json.dump(d, out_file, indent=4)
        print("JSON file successfully created")
    except Exception as e:
        print("Error during json save:",e)

