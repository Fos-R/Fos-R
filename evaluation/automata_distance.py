import argparse
import json
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
    parser.add_argument('--input', nargs=2, required=True, help="Select the language files.")
    args = parser.parse_args()

    with open(args.input[0]) as f:
        d1 = json.load(f)
    with open(args.input[1]) as f:
        d2 = json.load(f)

    print("JSD:",jsd_automata(d1,d2))
    print("Jaccard:",jaccard(d1,d2))
