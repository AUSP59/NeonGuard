<!--
SPDX-FileCopyrightText: 2025 AUSP59
SPDX-License-Identifier: Apache-2.0
-->

# NeonSec

High-performance C++20 streaming network log analyzer. Detects port scans, DDoS, brute-force, exfiltration, and beaconing in real time from CSV/NDJSON. Exposes Prometheus metrics and /healthz, outputs JSON/NDJSON, webhooks, and syslog. Extensible via plugins. Cross-platform CI, SBOM, CodeQL, reproducible builds.

Badges (update once the repo exists):
[CI](https://img.shields.io/github/actions/workflow/status/AUSP59/neonsec/ci.yml?branch=main) •
[License](https://img.shields.io/badge/license-Apache--2.0-blue.svg) •
[CoC](https://img.shields.io/badge/Code%20of%20Conduct-Contributor%20Covenant-ff69b4.svg)

---

## Features

- Input: CSV (header supported) and NDJSON (format auto-detect by extension)
- Engine: time-based sliding window, multi-threaded
- Detectors: portscan, ddos, bruteforce, exfil, beacon
- Outputs: stdout/file (rotation), webhook HTTP, syslog UDP
- Observability: Prometheus /metrics, /healthz, CIDR allowlist
- Ops: --follow, --since/--until, --fail-on, --summary, --config
- Extensibility: runtime plugins (shared libraries)
- Supply chain: SPDX/REUSE, SBOM (CycloneDX), CodeQL
- Packaging: CPack (TGZ/ZIP/DEB/RPM), Docker, K8s manifests, Helm chart
- Cross-platform: Linux/macOS/Windows (CMake ≥ 3.20, C++20)

---

## Quick Start

Build (Release):
$ cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
$ cmake --build build -j

Run (auto-detect format by extension):
$ ./build/neonsec analyze \
  --input examples/sample.csv --format-auto \
  --window 60 --outfmt json --summary \
  --metrics 0.0.0.0:9100 --metrics-allow 127.0.0.1/32 \
  --out-file findings.jsonl --out-rotate-bytes 1048576 \
  --webhook http://localhost:8080/hook \
  --syslog 127.0.0.1:514

CSV header (minimal):
ts,src_ip,dst_ip,src_port,dst_port,action,status,bytes,username
NDJSON fields mirror CSV (e.g., "ts", "src_ip", ...)

---

## CLI Overview

neonsec analyze --input <file|-> --format csv|ndjson|auto
  [--window SEC] [--rules FILE]
  [--metrics HOST:PORT] [--metrics-allow CIDR[,CIDR...]]
  [--threads N] [--outfmt text|json] [--out-file PATH] [--summary]
  [--fail-on <type>=<N>]... [--webhook URL] [--syslog HOST:PORT]
  [--follow] [--since TS] [--until TS]
  [--out-rotate-bytes N] [--config FILE]

neonsec bench --input <file> --format csv|ndjson [--iterations N]
neonsec selfcheck
neonsec validate-rules --file FILE
neonsec version

Exit codes: 0 OK, 1 usage/error, 2 invalid rules, 3 fail-on threshold triggered.

---

## Configuration (merge order: config < env < CLI)

Example config.json:
{
  "window": 60,
  "metrics": "0.0.0.0:9100",
  "metrics_allow": "127.0.0.1/32",
  "outfmt": "json",
  "out_file": "findings.jsonl",
  "summary": true,
  "webhook": "http://localhost:8080/hook",
  "syslog": "127.0.0.1:514",
  "threads": 4,
  "follow": true,
  "rotate_bytes": 1048576
}
Run: neonsec analyze --config config.json --input traffic.ndjson --format ndjson

---

## Detectors & Thresholds

- Port scan: many ports from src_ip → dst_ip
- DDoS: many unique attackers to the same dst_ip
- Brute-force: repeated failed auth per username
- Exfil: large bytes between src_ip → dst_ip
- Beacon: periodic connections with stable delta

Provide JSON thresholds via --rules FILE. Validate with: neonsec validate-rules --file FILE

---

## Outputs

- Stdout/file: --outfmt text|json, rotate with --out-rotate-bytes
- Webhook: POST JSON to --webhook
- Syslog: RFC5424-style over UDP via --syslog host:port

---

## Observability

- Prometheus: GET /metrics
- Health: GET /healthz
- Access control: --metrics-allow CIDR[,CIDR...]

Prometheus scrape:
- job_name: neonsec
  static_configs:
    - targets: ["localhost:9100"]

---

## Plugins

Shared library must export neonsec_register(PluginHook*).
Example: plugins/example_port50_block/ (policy: block port 50).
Load with: --plugin ./build/libneonsec_example.so

---

## Docker & Orchestration

Docker (distroless, non-root):
$ docker build -t neonsec:latest .
$ docker run --rm -p 9100:9100 -v $PWD/examples:/data:ro \
  neonsec:latest analyze --input /data/sample.csv --format-auto --metrics 0.0.0.0:9100

Kubernetes: k8s/deployment.yaml, k8s/service.yaml
Helm: charts/neonsec/ (edit values.yaml)
docker-compose: docker-compose.yml for local demo

---

## Testing & Quality

Build & run tests:
$ cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
$ cmake --build build -j
$ ctest --test-dir build --output-on-failure

Lint (Linux):
$ git ls-files '*.cpp' '*.hpp' | xargs -r clang-format -n --Werror
$ cppcheck --inline-suppr --enable=warning,performance,portability --std=c++20 --quiet . || true

CI runs on Ubuntu/macOS/Windows; CodeQL enabled.
Coverage is reported (advisory for new repos).

---

## Performance Tips

- Prefer std::string_view where safe; avoid copies on hot paths
- Reserve containers; reuse buffers
- Validate early; keep parsing linear
- Tune --threads and --window to ingestion rate

---

## Security

- Treat inputs as untrusted; never bypass validation
- Use trusted networks for webhook/syslog endpoints
- Container hardening: seccomp, no-new-privileges, read-only FS
- Vulnerability reports: AUSP59 — alanursapu@gmail.com (subject: [SECURITY] <title>)
See SECURITY.md and .well-known/security.txt

---

## Contributing & Community

Read CONTRIBUTING.md and CODE_OF_CONDUCT.md before PRs.
Conventional Commits + DCO sign-off required.
Maintainer: AUSP59 — alanursapu@gmail.com

---

## License & Compliance

- Apache-2.0 (see LICENSE)
- SPDX headers; REUSE metadata
- SBOM: SBOM.cdx.json (CycloneDX)
- Reproducible builds: SOURCE_DATE_EPOCH, file-prefix mapping

---

## Roadmap (high-level)

- Optional OTLP exporter (mTLS)
- Rule DSL & curated presets
- Additional streaming sources (stdin/pipe/socket)
- New detectors (e.g., lateral movement heuristics)

Issues and proposals welcome.