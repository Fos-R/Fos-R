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
            l.append(json.loads(f.read()))

    if len(l) == 0:
        print("No results")
        exit(1)

    s = f"## Experiment on {args.dataset}\n\n|Feature|Data level|Metric|"
    for dic in l:
        s += f"{dic['method']}|"
    s += "\n|-:|-:|-:|"
    for dic in l:
        s += ":---:|"
    for k,v in l[0]["results"].items():
        s += f"\n|{v['feature']}|{v['data']}|{v['metric']}|"
        # values = [dic[k] for dic in l]
        # best = get_best(values, k)
        for results in l:
            # if dic[k] == best:
                # s += f"**{dic[k]:.3f}**|"
            # else:
            s += f"{results['results'][k]['value']:.3f}|"

    output = f"results-{args.dataset}.md"
    print(f"Output file: {output}")
    with open(output, "w") as f:
        f.write(s)
