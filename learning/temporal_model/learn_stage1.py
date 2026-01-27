import numpy as np
import pandas as pd
import os
import json
import datetime
import argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Learn temporal models for Fos-R.')
    parser.add_argument('--input', required=True, help="Input directory.")
    parser.add_argument('--output', required=True, help="Output directory.")
    parser.add_argument('--offset', help="Offset from UTC (in hours).", type=float)
    args = parser.parse_args()
    args.offset = args.offset or 0 # default: consider it’s UTC

    print("Loading file")
    conn_input = os.path.join(args.input, "conn.log")
    flow = pd.read_csv(conn_input, header = 8, engine = "python", skipfooter = 1, sep = "\t", names = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp", "missed_bytes", "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "tunnel_parents", "ip_proto"])
    dates = (flow["ts"] + (60 * 60 * args.offset)) % (60 * 60 * 24)

    print("Computing model")
    bin_edges = np.linspace(0, 60 * 60 * 24, 24 * 4)  # one bin per 15 minutes
    bin_indices = np.digitize(dates, bin_edges)
    hist = np.bincount(bin_indices)

    data = { "histogram": hist[1:].tolist(), "metadata": { "creation_time": str(datetime.datetime.now()), "input_file": os.path.basename(os.path.normpath(args.input)) }}

    with open(os.path.join(args.output,'time_profile.json'), 'w') as f:
        json.dump(data, f)
