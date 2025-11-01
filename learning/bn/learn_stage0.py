import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import json
import datetime

# TODO: redo in Rust ?

if __name__ == '__main__':
    input_file = "cidds.csv"

    flow = pd.read_csv(input_file, header = 0, sep = ",")
    dates = flow["Date first seen"] % (1000000000*60*60*24)

    # TODO: take into account the timezone offset so the bins start at midnight + learn a different model for weekday and weekend

    bin_edges = np.linspace(0, 1000000000*60*60*24, 24*4)  # one bin per 15 minutes
    bin_indices = np.digitize(dates, bin_edges)
    hist = np.bincount(bin_indices)

    print(hist[1:])
    tz = "UTC" # TODO: depends on the dataset!
    # please do not use a dataset with an inconsistent UTC offset (mix of summer time and winter time, for example)

    data = { "histogram": hist[1:].tolist(), "metadata": { "creation_time": str(datetime.datetime.now()), "input_file": input_file }}

    with open('stage0.json', 'w') as f:
        json.dump(data, f)
