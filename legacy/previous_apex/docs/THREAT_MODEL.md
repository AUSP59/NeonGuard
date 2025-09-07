
# Threat Model (STRIDE)
Spoofing: signed releases (guide), DCO, CODEOWNERS.
Tampering: reviews, CI, CodeQL, Trivy, Scorecard.
Repudiation: signed commits recommended; DCO enforced.
Info Disclosure: no secrets; privacy document; sample-only data.
DoS: bounded queue, O(1) ops, configurable threads.
EoP: distroless, non-root runtime; least-privilege GitHub permissions.
