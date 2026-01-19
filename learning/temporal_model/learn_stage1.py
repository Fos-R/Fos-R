import numpy as np
import pandas as pd
# import matplotlib.pyplot as plt
import json
import datetime
import argparse

# TODO: redo in Rust ?

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Learn Bayesian networks for Fos-R.')
    parser.add_argument('--input', required=True, help="Select the input file. It must a csv.")
    parser.add_argument('--tz', required=True, help="Timezone of the dataset. Does not support datasets with an inconsistent offset (e.g., a mix of summer and winter time)")
    # parser.add_argument('--output', help="Select the output file to create.")
    args = parser.parse_args()

    # args.input = "cidds.csv"

    flow = pd.read_csv(args.input, header = 0, sep = ",")
    dates = flow["Date first seen"] % (1000000000*60*60*24)

    # TODO: take into account the timezone offset so the bins start at midnight + learn a different model for weekday and weekend

    bin_edges = np.linspace(0, 1000000000*60*60*24, 24*4)  # one bin per 15 minutes
    bin_indices = np.digitize(dates, bin_edges)
    hist = np.bincount(bin_indices)

    # print(hist[1:])

    data = { "histogram": hist[1:].tolist(), "metadata": { "creation_time": str(datetime.datetime.now()), "input_file": args.input }}

    with open('time_profile.json', 'w') as f:
        json.dump(data, f)
