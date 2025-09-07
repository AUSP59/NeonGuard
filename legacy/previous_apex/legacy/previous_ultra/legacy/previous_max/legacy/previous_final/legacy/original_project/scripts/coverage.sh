#!/usr/bin/env bash
set -euo pipefail
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DNEONSEC_BUILD_TESTS=ON -DCMAKE_CXX_FLAGS="--coverage" -DCMAKE_EXE_LINKER_FLAGS="--coverage"
cmake --build build -j
ctest --test-dir build --output-on-failure || true
if command -v gcovr >/dev/null; then
  gcovr -r . --xml -o coverage.xml
  gcovr -r . --html --html-details -o coverage.html
else
  echo "gcovr not found; installed coverage tools will be used if available."
fi
