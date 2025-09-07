
# Threat Model (STRIDE)

- Spoofing: signed releases (roadmap), DCO, CODEOWNERS.
- Tampering: PR reviews, CI, CodeQL, formatting/tidy checks.
- Repudiation: signed commits recommended, DCO required.
- Information Disclosure: avoid secrets in logs; simple schemas; privacy guidance.
- DoS: bounded queue backpressure; configurable threads; O(1) ops in hot path.
- EoP: least-privilege in CI and distroless runtime container.
