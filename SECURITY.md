<!--
SPDX-FileCopyrightText: 2025 AUSP59
SPDX-License-Identifier: CC-BY-4.0
-->

# Security Policy

We take the security of **NeonSec** seriously. This document explains how to report vulnerabilities, what’s in scope, and how we respond.

## Reporting a Vulnerability

Preferred: open a private advisory in GitHub → Security → “Report a vulnerability”  
Alternate: email **AUSP59** at **alanursapu@gmail.com** with subject “[SECURITY] <short title>”.

Please include (when possible): impact (CIA), affected commit/version, OS/build flags, minimal PoC or reproducer, steps to trigger, and any workarounds. We acknowledge within **3 business days**.

If sensitive details are required, request an ephemeral key exchange in the first email. A long-term PGP key will be published here when available.

## Coordinated Disclosure

1) Triage within 3 business days.  
2) Confirmation and initial assessment (≤7 days).  
3) Fix/mitigation target: ≤30 days (≤90 for complex or dependency issues).  
4) Patch release, GitHub Security Advisory, CVE via GitHub (when appropriate).  
5) Credit (opt-in, with consent). Timelines may accelerate for actively exploited or severe issues.

## Scope

In scope: repository source code, examples, build/CI (.github), Dockerfiles and images derived from this repo, Kubernetes/Helm manifests, documentation that could lead to unsafe configuration.

Out of scope: social engineering, physical attacks, account takeover outside this project; third-party infrastructure or services; unrealistic DoS (massive floods), or domain/DNS issues unrelated to this software.

## Safe-Harbor Testing

Allowed: non-destructive testing on your own systems and non-production datasets; bounded fuzzing; parser and config misuse tests.

Not allowed: exfiltrating real data; attacking infrastructure you don’t own; bypassing rate limits to degrade availability; publishing details/PoCs before a fix or coordinated disclosure.

Good-faith research under this policy will not be met with legal action.

## Severity & Triage

We use **CVSS v3.1** to guide severity:  
Critical (9.0–10), High (7.0–8.9), Medium (4.0–6.9), Low (0.1–3.9).  
We consider exploitability, required interaction, defaults, and realistic deployments.

## Supported Versions

Patched: **main** and the **latest release**.  
Previous minor may receive security-only fixes on a best-effort basis. Older releases should upgrade.

## Supply-Chain Security

- **CodeQL** runs for C/C++.  
- **SBOM (CycloneDX)** is provided; dependency alerts are reviewed.  
- Containers: run **as non-root**, enable **seccomp**, `no-new-privileges`, and read-only FS where possible.  
- Reproducible build flags are enabled; verify checksums/tags on releases.

If you find a vulnerable dependency path affecting NeonSec, report it with the SBOM entry or advisory link.

## Secrets & Sensitive Data

Do not commit credentials. If exposure occurs, rotate immediately and notify us. Sanitize logs/attachments before sharing.

## Optional Reporting Template

Title: <short, specific>  
Impact: <what an attacker gains / what breaks>  
Affected: <version/commit, platform, config>  
CVSS (suggested): <vector and score if known>  
Steps to Reproduce: 1) … 2) …  
PoC: <minimal input/config>  
Workaround: <if any>  
Reporter credit (optional): <Name/Handle> (<link>) — consent: yes/no

## Contact

Security contact: **AUSP59** — **alanursapu@gmail.com**

Last updated: 2025-09-05