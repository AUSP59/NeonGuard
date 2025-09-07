#!/usr/bin/env bash
set -euo pipefail
if ! command -v valgrind >/dev/null; then echo "valgrind not found"; exit 0; fi
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j
valgrind --quiet --error-exitcode=1 ./build/neonsec analyze --input examples/sample_logs.csv --format json >/dev/null
echo "valgrind: OK"
