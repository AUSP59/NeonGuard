# Risk Register
This document tracks technical, security, privacy, operational, and compliance risks with owners, likelihood, impact, and mitigations.

## Format
ID | Category | Description | Likelihood | Impact | Owner | Mitigation | Status
---|---|---|---|---|---|---|---
R-001 | Security | Input regex catastrophic backtracking | Low | High | Security Lead | Precompile and vet patterns; timeouts | Open
R-002 | Privacy | PII leakage via details | Medium | High | Privacy Lead | PII presets + truncation + masking | Mitigated
