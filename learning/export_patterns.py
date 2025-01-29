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
import math

import flowchronicle.dataloader as dl
from flowchronicle import search
from flowchronicle import model
from flowchronicle import attribute_value

feature_rename = {"Dst IP Addr": "DstIP", "Src IP Addr": "SrcIP", "In Packet": "FwdPkt", "Out Packet": "BwdPkt", "In Byte": "FwdByt", "Out Byte": "BwdByt", "Proto": "Proto", "Dst Pt": "DstPt", "Duration": "Duration", "Flags": "Flags"}

def describe_bn(bn, dataset):
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
        feature_name = dataset.col_name_map[bn.col_number_map[node]]
        intervals = dataset.cont_repr.get_cutpoints().get(feature_name)
        if intervals:
            domains = []
            for i in range(len(intervals)):
                if type(intervals.get(i)) == int:
                    domain = [intervals.get(i), intervals.get(i)+1]
                else:
                    assert intervals.get(i).closed == "right"
                    if feature_name == "Duration":
                        domain = [intervals.get(i).left, intervals.get(i).right]
                    else:
                        domain = [math.floor(intervals.get(i).left)+1, math.floor(intervals.get(i).right)+1]
                # print(feature_name, intervals.get(i))
                assert domain[0] < domain[1]
                domains.append(domain)
        else: # not an interval
            values = dataset.column_value_dict[feature_name]
            if type(values[0]) == np.int64 or type(values[0]) == int or type(values[0]) == float or type(values[0]) == np.float64:
                domains = [int(values[i]) for i in range(len(values))]
            else:
                assert type(values[0]) == str
                domains = [values[i] for i in range(len(values))]

        d["feature"] = { "type": feature_rename[feature_name], "domain": domains }
        d["partial_flow_number"] = bn.row_number_map[node]
        d["parents"] = [node_number[p] for p in bn.bn.get_parents(node)] # get index of parents
        out_cpt = []
        cpd = bn.bn.get_cpds(node)
        evidence = cpd.variables[1:]
        evidence_card = cpd.cardinality[1:]
        headers_list = []
        if evidence:
            out_cpt = { "parents_values": [], "probas": [] }
            col_indexes = np.array(list(product(*[range(j) for j in evidence_card])))
            for j in range(len(evidence_card)):
                column_header = [cpd.state_names[evidence[j]][d] for d in col_indexes.T[j]]
                headers_list.append(column_header)
            for j,l in enumerate(cpd.get_values().transpose()):
                couples = list(zip([int(v) for v in cpd.state_names[cpd.variable]], l.tolist()))
                probas = [0]*len(domains)
                for (i,p) in couples:
                    probas[i] = p
                assert(abs(sum(probas)-1) < 0.01)
                out_cpt["parents_values"].append([int(headers_list[k][j]) for k in range(len(evidence))])
                out_cpt["probas"].append(probas)
            d["cpt"] = out_cpt
        else: # no parents
            couples = [(int(cpd.state_names[cpd.variable][j]), float(cpd.get_values()[j][0])) for j in range(cpd.variable_card)]
            probas = [0]*len(domains)
            for (i,p) in couples:
                probas[i] = p
            assert(abs(sum(probas)-1) < 0.01)
            d["cpt"] = { "parents_values": [[]], "probas": [probas]}

        # TODO: in the domain, only keep the values with a non-null proba

        graph.append(d)

    return graph


if __name__ == "__main__":

    # parser = argparse.ArgumentParser(description='Train and generate synthetic network traffic.')
    # parser.add_argument('--input', required=True, help='Path to the input pcap file.')
    # parser.add_argument('--output', required=True, help='Path to the output file.')
    # args = parser.parse_args()


    print("start loading the model")

    m = model.Model.load_model("../models/medium/patterns.json.tmp")

    # m = model.Model.load_model(args.output)
    # m = model.Model.load_model(args.output+".tmp")

    c = m.cover
    dataset = c.dataset
    cover_stats = c.get_cover_stats()
    patterns_usage = cover_stats.get_pattern_usage()
    metadata = {}
    metadata["creation_time"] = str(datetime.datetime.now())
    metadata["input_file"] = os.path.split("test")[-1]
    # metadata["input_file"] = os.path.split(args.input)[-1] // FIXME
    patterns = []

    weights = []


    for p in m.pattern_set:
        d = {}
        partial_flows = []
        # print(p.pattern)
        for row,pf in enumerate(p.pattern):
            current_pf = []
            for k,v in pf.pattern.items():
                col = dataset.col_name_map[k]
                # print(k,v)
                # print(dataset.column_value_dict)
                # print(col)
                # print(feature_rename[col])
                if v.attr_type == attribute_value.AttributeType.FIX:
                    intervals = dataset.cont_repr.get_cutpoints().get(col)
                    val = dataset.column_value_dict[col][v.value]
                    domain = []
                    if intervals: # Duration should be not FIXED
                        if type(intervals.get(val)) == int:
                            domain = [[intervals.get(val), intervals.get(val)+1]]
                        else:
                            assert intervals.get(val).closed == "right"
                            domain = [[math.floor(intervals.get(val).left)+1, math.floor(intervals.get(val).right)+1]]
                        assert domain[0] < domain[1]
                    elif type(val) == np.int64 or type(val) == int or type(val) == float or type(val) == np.float64:
                        domain = [int(val)]
                    else:
                        print(type(val))
                        assert type(val) == str
                        domain = [val]
                    current_pf.append({ "type": "Fixed", "feature": { "type": feature_rename[col], "domain": domain } })
                elif v.attr_type == attribute_value.AttributeType.USE_PLACEHOLDER:
                    assert col == "Dst IP Addr" or col == "Src IP Addr"
                    (p_r,p_col) = placeholders[v.value]
                    if p_col == "Dst IP Addr" and col == "Dst IP Addr":
                        current_pf.append({ "type": "ReuseDrcAsDst", "row": p_r })
                    elif p_col == "Src IP Addr" and col == "Dst IP Addr":
                        current_pf.append({ "type": "ReuseSrcAsDst", "row": p_r })
                    elif p_col == "Dst IP Addr" and col == "Src IP Addr":
                        current_pf.append({ "type": "ReuseDstAsSrc", "row": p_r })
                    elif p_col == "Src IP Addr" and col == "Src IP Addr":
                        current_pf.append({ "type": "ReuseSrcAsSrc", "row": p_r })
                elif v.attr_type == attribute_value.AttributeType.SET_PLACEHOLDER:
                    assert col == "Dst IP Addr" or col == "Src IP Addr"
                    placeholders[v.value] = (row,col)

            partial_flows.append(current_pf)
        d["partial_flows"] = partial_flows
        if p.bn.bn:
            d["bayesian_network"] = describe_bn(p.bn, dataset)
        else:
            d["bayesian_network"] = []
        # assert len(partial_flows)*(len(df.columns)-1) - len(pf.pattern) == len([k for pf in partial_flows for k in pf if k.get("type")=="Free"]) # check there is the correct number of "Free" cells
        patterns.append(d)
        weights.append(patterns_usage[p])

    base_bn = m._ChunkyModel__base_bn
    patterns.append({"partial_flows": [[]], "bayesian_network": describe_bn(base_bn, dataset)})
    weights.append(m.cover.get_empty_pattern_usage())
    d = {}
    d["pattern_weights"] = weights
    d["metadata"] = metadata
    d["patterns"] = patterns
    # print(d)
    try:
        # out_file = open(args.output, "w") // FIXME
        out_file = open("patterns.json", "w")
        json.dump(d, out_file)
        print("JSON file successfully created")
    except Exception as e:
        print("Error during json save:",e)

