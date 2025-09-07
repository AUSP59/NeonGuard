#!/usr/bin/env bash
set -euo pipefail
build_dir=${1:-build}
$build_dir/neonsec analyze --input examples/sample_logs.csv --format json > $build_dir/out.json || true
# smoke: file exists and not empty
test -s $build_dir/out.json
