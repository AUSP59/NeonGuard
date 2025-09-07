# Benchmarks
Opt-in micro-benchmark runner for ingest-like workloads.

## Build
```bash
cmake -S . -B build -DNEONSEC_ENABLE_BENCH=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

## Run
```bash
cat /var/log/syslog | ./build/bench/bench_neonsec
```
Outputs: processed lines, elapsed ms, lines/sec.