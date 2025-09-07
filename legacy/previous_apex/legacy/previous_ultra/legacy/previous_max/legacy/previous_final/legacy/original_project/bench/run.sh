#!/usr/bin/env bash
set -euo pipefail
N=${1:-200000}
python3 bench/generate.py $N > /tmp/neonsec_bench.csv
time ./build/neonsec analyze --input /tmp/neonsec_bench.csv --format json >/dev/null
