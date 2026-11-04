#!/usr/bin/env python3
"""time_it.py RUNS OK_CODES -- COMMAND...  Median wall seconds of RUNS runs of COMMAND.

The clock runs around the child process only (no interpreter start-up inside the
timed region), and a run that ends with an exit code outside OK_CODES (for example
`0,1`: success and "found something") stops the benchmark: a crashed tool is not
a fast tool. The value printed for it is `FAILED(exit N)`, so the timing table
cannot show a crash as a time."""
import statistics
import subprocess
import sys
import time

runs, ok = int(sys.argv[1]), {int(c) for c in sys.argv[2].split(",")}
cmd = sys.argv[sys.argv.index("--") + 1 :]
times = []
for _ in range(runs):
    start = time.perf_counter()
    code = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
    times.append(time.perf_counter() - start)
    if code not in ok:
        sys.stdout.write(f"FAILED(exit {code})\n")
        sys.exit(f"time_it: `{' '.join(cmd)}` exited {code}, expected one of {sorted(ok)}")
sys.stdout.write(f"{statistics.median(times):.2f}\n")
