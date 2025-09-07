
# Threat Model (STRIDE)

Assets: source code, CI, container images.
Threats/Mitigations:
- Spoofing: signed releases (roadmap); CODEOWNERS & DCO.
- Tampering: PR reviews, CI, CodeQL.
- Repudiation: signed commits (recommended), DCO.
- Info disclosure: no secrets; review checklist.
- DoS: bounded algorithms; no unbounded allocations.
- EoP: least-privilege in CI; distroless runtime.
