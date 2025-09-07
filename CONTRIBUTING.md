<!--
SPDX-FileCopyrightText: 2025 AUSP59
SPDX-License-Identifier: CC-BY-4.0
-->

# Contributing Guide

Thank you for your interest in contributing! By participating, you agree to follow our **Code of Conduct** (see `CODE_OF_CONDUCT.md`).

**Maintainer contact:** AUSP59 — <alanursapu@gmail.com>

---

## Quick Start (TL;DR)

1. Fork the repo and create a branch from `main`:
    - `feat/<topic>`, `fix/<issue>`, `docs/<area>`, etc.
2. Build, format, and test locally (see below).
3. Commit using **Conventional Commits** and **DCO sign-off**.
4. Open a Pull Request (PR) with a clear description and link issues.

---

## Development Setup

**Requirements**
- C++20 compiler (GCC 11+/Clang 13+/MSVC 2022+)
- CMake ≥ 3.20
- Linux/macOS/Windows
- Optional (Linux): `clang-format`, `cppcheck`, `gcovr`, `lcov`
- Optional: Docker, VS Code Dev Containers

**Build & Test**

    cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
    cmake --build build -j
    ctest --test-dir build --output-on-failure

**Release Build**

    cmake -S . -B build-release -DCMAKE_BUILD_TYPE=Release
    cmake --build build-release -j

**Coverage (Linux)**

    cmake -S . -B build-cov -DCMAKE_BUILD_TYPE=Debug
    cmake --build build-cov -j
    ctest --test-dir build-cov --output-on-failure
    gcovr -r . --branches --xml -o coverage.xml

**Formatting & Static Analysis (Linux)**

    git ls-files '*.cpp' '*.hpp' | xargs -r clang-format -n --Werror
    cppcheck --inline-suppr --enable=warning,performance,portability --std=c++20 --quiet . || true

**Pre-commit (optional)**

    pip install pre-commit
    pre-commit install
    pre-commit run --all-files

---

## Coding Standards

- **C++20**, prefer RAII, avoid raw `new/delete`.
- Keep functions small, names descriptive, and interfaces minimal.
- Use `std::string_view` when safe; avoid unnecessary copies.
- Validate all untrusted input; fail fast with clear errors.
- Ensure **thread-safety** and document invariants.
- Maintain **portability** (Linux/macOS/Windows).
- Public headers must include concise, useful comments.

---

## Tests

- Add unit tests for new logic and edge cases.
- Keep tests deterministic and fast.
- For detector/streaming paths, include integration tests when possible.
- All tests must pass on Linux/macOS/Windows.

---

## Git Hygiene

**Branching**
- Branch from `main`: `feat/<topic>`, `fix/<issue>`, `docs/<area>`

**Commit Messages (Conventional Commits)**
- `feat:`, `fix:`, `docs:`, `test:`, `build:`, `ci:`, `refactor:`, `perf:`, `chore:`
- Subject in imperative mood, ≤72 chars; add body for context if needed.

**DCO (Developer Certificate of Origin)**
- Every commit must be signed off:

      Signed-off-by: Your Name <your.email@example.com>

- Use `git commit -s -m "feat: add awesome detector"`

---

## Pull Requests

Before opening a PR, ensure:
- [ ] Builds on **all** OSes (or explains platform limits).
- [ ] Tests added/updated and passing (`ctest`).
- [ ] Formatting check passes on Linux (`clang-format -n`).
- [ ] Public APIs/docstrings updated; README/examples adjusted if behavior changes.
- [ ] No secrets in code, tests, or CI.
- [ ] Commits include **DCO sign-off**.

In the PR:
- Link related issues.
- Describe the change, rationale, and any trade-offs.
- For security-sensitive changes, include a brief risk assessment and mitigations.

---

## Dependencies & Licensing

- Favor minimal dependencies.
- Licenses must be compatible with **Apache-2.0** (e.g., MIT/BSD/Apache-2.0).
- Include SPDX headers in new files and follow **REUSE** conventions.
- Avoid GPL/LGPL unless pre-approved by maintainers.

---

## Security

- Never weaken input validation, sandboxing, or logging hygiene.
- Report vulnerabilities privately to **AUSP59** at **alanursapu@gmail.com**  
  Subject: `[SECURITY] <title>`; we acknowledge within **3 business days**.
- We follow coordinated disclosure.

---

## CI Expectations

- CI runs on Linux/macOS/Windows: build + tests.
- Lint runs on Linux; CodeQL runs on Ubuntu.
- Coverage is reported; projects may enforce thresholds over time.

---

## Governance

- Maintainers review PRs; security-affecting changes require **two approvals**.
- Disclose conflicts of interest; recuse when necessary.
- Decision-making values: security, clarity, testability, user impact.

---

## Code of Conduct

Participation is governed by the `CODE_OF_CONDUCT.md`.  
Reports: **AUSP59** — <alanursapu@gmail.com>

---

## Release Notes & SemVer

- Follow **SemVer** for public CLI/API.
- Update CHANGELOG entries in PRs for user-visible changes.

---

## Thank You

Your contributions make this project better. If anything is unclear, please open an issue and we’ll help you get started.