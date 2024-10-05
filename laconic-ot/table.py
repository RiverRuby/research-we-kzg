import os
import json
import tabulate

from fractions import Fraction

PATH = "target/criterion"
SIZES = list(range(3, 10))
SUB_DIRS = [
    ("Hash (Time)", "laconic_ot_commit"),
    ("Send (Time)", "laconic_ot_send"),
    ("Recv (Time)", "laconic_ot_recv"),
]

def fmt_time(ns):
    if ns < 1_000:
        return f"{ns:.2f} ns"

    if ns < 1_000_000:
        return f"{ns / 1_000:.2f} µs"

    ms = ns / 1_000_000

    if ms < 1_000:
        return f"{ms:.2f} ms"

    s = ms / 1_000

    if s < 60:
        return f"{s:.2f} s"

    m = s / 60
    s = s % 60

    return f"{m:.0f}:{round(s)} m"

table = []

header = ["Database Size"]
for (name, _) in SUB_DIRS:
    header.append(name)

for size in SIZES:
    row = []
    row.append(f"$2^{{{size}}}$")
    for (name, sub_dir) in SUB_DIRS:
        path = os.path.join(PATH, sub_dir, f"{size}", "new", "sample.json")
        data = json.loads(open(path, "r").read())

        iters = data["iters"]
        times = data["times"]

        assert len(iters) == len(times)

        # compute average time
        total = 0
        for (iter, time) in zip(iters, times):
            total += Fraction(time) / iter

        # format time
        average_ns = total / len(iters)
        time = fmt_time(average_ns)
        print(f"{sub_dir} {size} {time}")
        row.append(time)
    table.append(row)

print(tabulate.tabulate(
    table,
    headers=header,
    tablefmt="github",
    colalign=("center", "center", "center", "center"),
    stralign="center",
))
