
# Threat Model (STRIDE)

- Spoofing: signed releases (guide), DCO, CODEOWNERS.
- Tampering: reviews, CI, CodeQL, Trivy, Scorecard.
- Repudiation: signed commits recommended; DCO required.
- Info Disclosure: no secrets; privacy doc; sample data only.
- DoS: bounded queue, O(1) ops, threads configurable.
- EoP: distroless, non-root user; least-privilege GH permissions.
