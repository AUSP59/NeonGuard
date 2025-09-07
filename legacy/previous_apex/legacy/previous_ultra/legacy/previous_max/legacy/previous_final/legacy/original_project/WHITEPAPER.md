
# NeonSecure Network System — Technical Whitepaper (Overview)

**Goal:** High-integrity, privacy-preserving, offline-capable network finding pipeline in C++ with deterministic outputs and verifiable artifacts.

- Streaming parser for CSV/NDJSON with strict/dry modes
- Rules engine for `(type,key,details)` findings
- Deterministic ordering and summaries for reproducible triage
- Privacy: redaction, pseudonymization (HMAC), optional ASCII-only
- Integrity: per-record SHA-256, run prolog/epilogue digests, indexing
- Operability: rate-limit, progress, metrics, rotation, bucketed summaries
- Extensibility: plugins, schema, configs, CLI subcommands
- Security: hardening flags, seccomp profile example, BiDi sanitization
