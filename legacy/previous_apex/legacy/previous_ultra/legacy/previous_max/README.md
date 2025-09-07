
# NeonSec OSS (v2.0.0)

A production-grade, zero-dependency C++20 network log analyzer with **NDJSON + CSV**, **plugin system**, **Prometheus metrics endpoint**, **fuzzers**, **tests**, **CI (multi-OS + CodeQL)**, **coverage**, **container (distroless)**, **governance**, **security**, **SBOM**, and **release verification tools**.

## Highlights
- C++20 + CMake, strict warnings, optional ASan/UBSan, LTO
- Sliding-window detectors (port-scan, DDoS unique attackers)
- **NDJSON & CSV ingestion**
- **Plugin system** with example shared library
- **Prometheus metrics** on `:9100` (text format)
- **Multithreaded pipeline** with bounded queue (backpressure)
- Unit tests (`ctest`), fuzz target (libFuzzer/Clang)
- CI: Linux/macOS/Windows + CodeQL + clang-format/tidy checks + coverage
- Docker (distroless), Dev Container
- Apache-2.0, NOTICE, DCO, CODEOWNERS
- Threat model, Audit checklist, Whitepaper, Privacy & Reproducibility
- **SBOM (CycloneDX)**

## Quick Start
```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release -j
./build/neonsec analyze --input examples/sample.csv --format csv --window 60 --metrics :9100
# open http://localhost:9100/metrics
```

## Plugins
Build creates `libneonsec_example.*`. Load with:
```
./build/neonsec analyze --input examples/sample.csv --format csv --plugin ./build/libneonsec_example.so
```

## Inputs
- CSV header: `ts,src_ip,dst_ip,src_port,dst_port,action,status,bytes,username`
- NDJSON keys: `"ts","src_ip","dst_ip","src_port","dst_port","action","status","bytes","username"`

See `examples/` for sample data.

## Docs
- `docs/ARCHITECTURE.md` – data flow and modules
- `docs/THREAT_MODEL.md` – STRIDE
- `docs/WHITEPAPER.md` – rationale and approach
- `docs/PRIVACY.md` – data handling considerations
- `docs/REPRODUCIBILITY.md` – deterministic builds guidance
- `docs/RELEASE_VERIFICATION.md` – how to verify a release end-to-end
