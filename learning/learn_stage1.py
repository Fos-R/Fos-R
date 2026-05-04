import numpy as np
import pandas as pd
import os
import json
import datetime
import argparse
import matplotlib.pyplot as plt

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Learn temporal models for Fos-R.')
    parser.add_argument('--input', required=True, help="Input directory.")
    parser.add_argument('--output', required=True, help="Output directory.")
    parser.add_argument('--offset', help="Offset from UTC (in hours).", type=float)
    parser.add_argument('--bin-count', help="Number of bins per day (by default, 15-min bins)", type=int)
    args = parser.parse_args()
    args.offset = args.offset or 0 # default: consider it’s UTC
    bin_count = args.bin_count or 24 * 4

    print("Loading file")
    conn_input = os.path.join(args.input, "conn.log")
    flow = pd.read_csv(conn_input, header = 8, engine = "python", skipfooter = 1, sep = "\t", names = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp", "missed_bytes", "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "tunnel_parents", "ip_proto"])
    dates = (flow["ts"] + (60 * 60 * args.offset)) % (60 * 60 * 24)

    print("Computing model")
    bin_edges = np.linspace(0, 60 * 60 * 24, bin_count + 1) # fence post problem
    bin_indices = np.digitize(dates, bin_edges)
    hist = np.bincount(bin_indices)[1:].tolist()
    hist = (hist + bin_count * [0])[:bin_count] # pad with zero
    assert len(hist) == bin_count

    data = { "histogram": hist, "metadata": { "creation_time": str(datetime.datetime.now()), "input_file": os.path.basename(os.path.normpath(args.input)) }}

    with open(os.path.join(args.output,'time_profile.json'), 'w') as f:
        json.dump(data, f)

    plt.stairs(hist, bin_edges, fill=True)
    plt.xlabel("Time of the day")
    plt.ylabel('Flow count')
    plt.title(f'Temporel model from {os.path.basename(os.path.normpath(args.input)) }')
    plt.grid(True)
    plt.savefig(os.path.join(args.output,f"temporal_model.png"), dpi=300, bbox_inches="tight")
    plt.clf()

