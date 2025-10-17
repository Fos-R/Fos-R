import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import json
import datetime

input_file = "cidds.csv"

flow = pd.read_csv(input_file, header = 0, sep = ",")
dates = flow["Date first seen"] % (1000000000*60*60*24)

bin_edges = np.linspace(0, 1000000000*60*60*24, 24*4)  # one bin per 15 minutes
bin_indices = np.digitize(dates, bin_edges)
hist = np.bincount(bin_indices)

print(hist[1:])

data = { "histogram": hist[1:].tolist(), "metadata": { "creation_time": str(datetime.datetime.now()), "input_file": input_file }}

with open('stage0.json', 'w') as f:
    json.dump(data, f)
