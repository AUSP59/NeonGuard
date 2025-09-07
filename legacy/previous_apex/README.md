
# NeonSec OSS (v4.0.0, APEX)

A reference-grade, zero-runtime-deps C++20 network log analyzer with **CSV + NDJSON**, **plugin system**, **Prometheus metrics** (host/port configurable, optional **TLS** with OpenSSL), **JSON or text findings**, **benchmarks**, **tests**, **fuzzers**, **multi-OS CI**, **CodeQL**, **coverage gates**, **Trivy & Scorecard**, **multi-arch containers**, **provenance/signing (Cosign)**, **CPack (DEB/RPM)**, **Dev Container**, **governance/ethics/accessibility/inclusion/sustainability**, **SBOM**, and **release verification**.

## Quick Start
```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release -j
./build/neonsec analyze --input examples/sample.csv --format csv --window 60 --metrics 0.0.0.0:9100 --outfmt json
# TLS metrics (requires -DNEONSEC_WITH_TLS=ON at build):
./build/neonsec analyze --input examples/sample.csv --format csv --metrics 0.0.0.0:9100 --tls-cert cert.pem --tls-key key.pem
# Benchmark parser only
./build/neonsec bench --input examples/sample.csv --format csv --iterations 3
```

## Rules (JSON)
```json
{
  "portscan_attempts": 20,
  "ddos_events": 200,
  "ddos_unique": 50,
  "bruteforce_failures": 10
}
```
Pass via `--rules rules.json`.

## Packaging
- `cpack -G DEB` or `-G RPM` to generate native packages.
- Container: Dockerfile builds with TLS support enabled (`libssl-dev`).

See `docs/` for architecture, security, compliance, release process, and more.
