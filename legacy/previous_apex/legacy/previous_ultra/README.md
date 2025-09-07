
# NeonSec OSS (v3.0.0)

A production-grade, zero-dependency C++20 network log analyzer with **CSV + NDJSON**, **plugin system**, **Prometheus metrics** (bind host configurable), **JSON or text findings**, **tests**, **fuzzers**, **multi-OS CI**, **CodeQL**, **coverage gates**, **Trivy & Scorecard**, **Docker (distroless pinned)**, **Dev Container**, **full governance & ethics**, **SBOM**, and **release verification**.

## Highlights
- C++20 + CMake with strict hardening flags; optional LTO, ASan/UBSan
- Sliding-window detectors (port-scan, DDoS unique attackers)
- CSV & NDJSON ingestion
- Plugin system (shared libraries); example policy plugin
- Prometheus metrics endpoint (`--metrics host:port`)
- Findings output `--outfmt text|json`
- Multithreaded pipeline with backpressure
- Unit tests + fuzz target (Clang)
- CI: Linux/macOS/Windows, CodeQL, clang-format/tidy, cppcheck
- Coverage gate (gcovr `--fail-under-line 80`)
- Security scans: **Trivy**; OpenSSF **Scorecard**
- Apache-2.0, NOTICE, SPDX headers, DCO, CODEOWNERS
- Threat model, Security runbook, Audit checklist, Privacy, Ethics, Inclusion, Accessibility, Sustainability
- SBOM (CycloneDX)
- Release verification & signing guide
- Dependabot for GH Actions & Docker

## Quick Start
```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release -j
./build/neonsec analyze --input examples/sample.csv --format csv --window 60 --metrics 0.0.0.0:9100 --outfmt json
# open http://localhost:9100/metrics
```

## Plugins
```
./build/neonsec analyze --input examples/sample.csv --format csv --plugin ./build/libneonsec_example.so
```

## Optional PCAP plugin
Enable build with `-DNEONSEC_WITH_PCAP=ON` (requires libpcap). See `plugins/pcap_ingest/`.

See `docs/` for architecture, security, compliance, and governance.
