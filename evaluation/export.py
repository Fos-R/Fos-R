import os
import argparse
import json

def get_best(values, k):
    # TODO: améliorer, ajuster selon les métriques et ne pas compter la référence
    return min(values)

def extract_category(name):
    elements = name.split()
    if elements[0] in ["Flow","Pkt","Pcap","Vendi"]:
        return elements[0], " ".join(elements[1:])
    else:
        return "", name

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Format the data to Markdown')
    parser.add_argument('--dataset', required=True, help="Select the folder with json files.")
    # parser.add_argument('--output', required=True, help="Select the output file.")

    args = parser.parse_args()

    objects = os.scandir(args.dataset)
    l = []
    for entry in objects:
        if entry.is_file() and '.json' in entry.name:
            f = open(entry.path)
            l.append(json.loads(f.read()))
    print(l)
    if len(l) == 0:
        print("No results")
        exit(1)

    s = f"# Experiment on {args.dataset}\n\n|Metric|||"
    for dic in l:
        s += f"{dic['method']}|"
        s += "\n|-:|-:|:-:|"
    for dic in l:
        s += ":---:|"
    for k in l[0].keys():
        first, second = extract_category(k)
        if k == "method":
            continue
        s += f"\n|{first}|{second}||"
        values = [dic[k] for dic in l]
        best = get_best(values, k)
        for dic in l:
            if dic[k] == best:
                s += f"**{dic[k]:.3f}**|"
            else:
                s += f"{dic[k]:.3f}|"

    print(s)
    output = f"results-{args.dataset}.md"
    with open(output, "w") as f:
        f.write(s)
