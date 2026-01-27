import numpy as np
import pandas as pd
import os
import json
import datetime
import argparse
import pytz
import matplotlib.pyplot as plt

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Learn Bayesian networks for Fos-R.')
    parser.add_argument('--input', required=True, help="Select the input directory.")
    parser.add_argument('--output', required=True, help="Select the output directory.")
    parser.add_argument('--offset', help="Offset from UTC (in hours).", type=float)
    args = parser.parse_args()
    args.offset = args.offset or 0

    print("Loading file")
    conn_input = os.path.join(args.input, "conn.log")

    print("Computing model")
    # read the CSV
    flow = pd.read_csv(conn_input, header = 8, engine = "python", skipfooter = 1, sep = "\t", names = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp", "missed_bytes", "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "tunnel_parents", "ip_proto"])
    dates = (flow["ts"] + (60 * 60 * args.offset)) % (60*60*24)

    bin_edges = np.linspace(0, 60*60*24, 24*4)  # one bin per 15 minutes
    bin_indices = np.digitize(dates, bin_edges)
    hist = np.bincount(bin_indices)

    plt.plot(hist[1:])
    data = { "histogram": hist[1:].tolist(), "metadata": { "creation_time": str(datetime.datetime.now()), "input_file": os.path.basename(os.path.normpath(args.input)) }}

    with open(os.path.join(args.output,'time_profile.json'), 'w') as f:
        json.dump(data, f)
