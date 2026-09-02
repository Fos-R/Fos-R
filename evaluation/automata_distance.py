#!/usr/bin/env python3

import argparse
import json
import os
from math import floor, log2, pow

def jsd_automata(distrib1, distrib2):
    score = 0
    all_words = set(distrib1.keys()).union(set(distrib2.keys()))
    for w in all_words:
        p1 = distrib1.get(w) or 0
        p2 = distrib2.get(w) or 0
        m = 0.5 * (p1 + p2)
        if p1 > 0:
            score += 0.5 * p1 * log2(p1 / m)
        if p2 > 0:
            score += 0.5 * p2 * log2(p2 / m)
    return score


def jaccard(distrib1, distrib2):
    true_words = set(distrib1.keys())
    learned_words = set(distrib2.keys())
    return 1-len(true_words.intersection(learned_words))/len(true_words.union(learned_words))

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Compute the distances between learned automata.')
    parser.add_argument('--input', nargs=2, required=True, help="Select the automata directories.")
    args = parser.parse_args()

    dir_list1 = os.listdir(args.input[0])
    dir_list2 = os.listdir(args.input[1])
    files = set([os.path.split(p)[1] for p in dir_list1 if p.endswith("-language.json")]).intersection([os.path.split(p)[1] for p in dir_list2 if p.endswith("-language.json")])

    for file in files:
        with open(os.path.join(args.input[0], file)) as f:
            d1 = json.load(f)
        with open(os.path.join(args.input[1], file)) as f:
            d2 = json.load(f)
        print(f"{file}")
        print(f"  JSD: {jsd_automata(d1,d2)}")
        print(f"  Jaccard {file}: {jaccard(d1,d2)}")
