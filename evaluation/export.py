#!/usr/bin/env python3

import os
import argparse
import json

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Format the data to Markdown')
    parser.add_argument('--dataset', required=True, help="Select the folder with json files.")

    args = parser.parse_args()

    objects = os.scandir(args.dataset)
    l = []
    for entry in objects:
        if entry.is_file() and '.json' in entry.name:
            print(f"Processing {entry.name}")
            f = open(entry.path)
            dic = json.loads(f.read())
            if dic['method'] == "Reference": # Reference always at the beginning
                l.insert(0, dic)
            elif dic['method'] == "Fos-R": # Fos-R always in the last position
                l.append(dic)
            else:
                l.insert(1, dic)

    if len(l) == 0:
        print("No results")
        exit(1)

    s = f"# Experimental results\n\n|Feature|Data level|Metric|"
    for dic in l:
        s += f"{dic['method']}|"
    s += "\n|-:|-:|-:|"
    for dic in l:
        s += ":---:|"
    # best_position = [0]*len(l)
    min_position = [0]*len(l)
    for k,v in l[0]["results"].items():
        if v['metric']=="Mutual Information" or v['metric']=="Spearman corr. difference":
            continue
        s += f"\n|{v['feature']}|{v['data']}|{v['metric']}|"
        # values_diff = [abs(l[i]['results'][k]['value']-l[0]['results'][k]['value']) for i in range(1,len(l))] # remove reference
        # index_best = min(enumerate(values_diff), key=lambda x: x[1])[0] + 1 # +1 because the reference is the first column
        if v['metric'] == "Vendi":
            index_min = None
        else:
            values = [abs(l[i]['results'][k]['value']) for i in range(1,len(l))] # remove reference
            index_min = min(enumerate(values), key=lambda x: x[1])[0] + 1 # +1 because the reference is the first column
            min_position[index_min] += 1
        # best_position[index_best] += 1
        for i,results in enumerate(l):
            # if i == index_best and i == index_min:
                # s += f"\\textit{{\\textbf{{{results['results'][k]['value']:.3f}}}}}|"
            # elif i == index_best:
            if i == index_min:
                s += f"\\textbf{{{results['results'][k]['value']:.3f}}}|"
            # elif i == index_min:
                # s += f"\\textit{{{results['results'][k]['value']:.3f}}}|"
            else:
                s += f"{results['results'][k]['value']:.3f}|"
    # index_best = max(enumerate(best_position), key=lambda x: x[1])[0]
    # s += f"\n|Overall closest to Reference||||"
    # for i,v in enumerate(best_position):
    #     if i > 0:
    #         if i == index_best:
    #             s += f"\\textbf{{{v}}}|"
    #         else:
    #             s += f"{v}|"
    index_min = max(enumerate(min_position), key=lambda x: x[1])[0]
    s += f"\n|Overall closest||||"
    for i,v in enumerate(min_position):
        if i > 0:
            if i == index_min:
                s += f"\\textbf{{{v}}}|"
            else:
                s += f"{v}|"

    output = f"results-{args.dataset}.md"
    print(f"Output file: {output}")
    with open(output, "w") as f:
        f.write(s)
