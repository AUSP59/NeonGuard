
# Threat Model (STRIDE-lite)

- **Spoofing:** BiDi control stripping; ASCII-only; validation of mandatory fields.
- **Tampering:** Per-record SHA-256 `sig=`, stream epilogue digest; index for random access.
- **Repudiation:** `--run-id`, prolog, manifest in `--artifact-dir`; summary/audit JSONs.
- **Information Disclosure:** `--redact`, `--redact-patterns`, pseudonymization HMAC with user-provided salt.
- **Denial of Service:** `--rate-limit`, `--progress`, `--dedupe-window`, memory stats, rlimits.
- **Elevation of Privilege:** Hardening flags, seccomp profile example; no dynamic code execution in core.
