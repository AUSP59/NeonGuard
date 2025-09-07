# Threat Model (STRIDE) — NeonSec
*Generated: 2025-09-07*

## Scope
- **Data sources:** network logs, PCAP streams, syslog, application logs.
- **Components:** parsers, detectors (port-scan, DDoS, brute-force), plugin runtime, metrics exporter, CLI/daemon, storage.
- **Deployments:** containerized (Docker/K8s) and bare-metal.

## Assumptions
- Config files are controlled by operators.
- Time sync (NTP) is reliable within ±1s for correlation.
- Metrics endpoint is internal-only.

## Assets
- Integrity of detection results
- Availability of processing pipeline
- Confidentiality of logs (PII, secrets)

## STRIDE Analysis
| Category | Example Threat | Impact | Mitigations |
|---|---|---|---|
| Spoofing | Forged source IPs in logs | False positives/negatives | Ingest chain of custody; mark untrusted fields; detector heuristics resilient to spoofing |
| Tampering | Corrupt PCAP/log inputs | Crash or misclassification | Input validation, fuzzing (ASan/UBSan), schema checks, bounded parsing |
| Repudiation | Missing audit trail | Forensic gaps | Structured JSON logs with request IDs, immutable storage (optional) |
| Information Disclosure | Sensitive fields in metrics/logs | Data leakage | Redaction rules, opt-in PII masking, metrics allowlist |
| Denial of Service | Pathological inputs | Resource exhaustion | Back-pressure, timeouts, rate limits, circuit breakers, watchdogs |
| Elevation of Privilege | Untrusted plugins | RCE via plugin | Signed plugins, restricted plugin dirs, drop caps (K8s), seccomp/apparmor profiles |

## Design Controls
- **Build hardening:** stack protector, RELRO/Now, PIE, Fortify, LTO (Release).
- **Runtime checks:** optional ASan/UBSan builds; fuzz harnesses.
- **Supply chain:** SBOM, CodeQL, SLSA provenance workflow.
- **Observability:** Prometheus metrics, JSON logs (recommendation), Grafana dashboards.

## Data Flow (DFD)
1. Sources → Ingest → Parser → Detector Pipeline → Metrics/Alerts → Sinks (files, stdout, exporters).
2. Configuration service reads YAML/JSON config; CLI validates with schema.
3. Optional plugin loader reads signed *.so from a restricted directory.

## Test Plan (Security)
- **Fuzz targets:** parsers (lines/pcap), plugin manifest loader (JSON/YAML).
- **Sanitizers:** nightly CI with ASan/UBSan.
- **Coverage:** keep ≥80% for parsers & plugins.
- **Benchmarks:** throughput (MiB/s), latency (p50/p95/p99).

## Residual Risks
- Evasion via novel patterns (monitor drift; retrain heuristics).
- Source spoofing (requires upstream auth/attestation).
- Operator misconfiguration (validate + safe defaults).

## Appendix
- K8s hardening: runAsNonRoot, readOnlyRootFilesystem, drop CAP_SYS_ADMIN, seccompProfile: RuntimeDefault.