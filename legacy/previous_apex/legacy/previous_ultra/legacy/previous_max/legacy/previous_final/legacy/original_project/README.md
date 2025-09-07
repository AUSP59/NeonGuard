# Neon Secure Network System (neonsec) — OMEGA

Production‑ready C++20 security analytics engine and CLI. Dependency‑free core, portable, hardened, auditable.

## Key Features
- Sliding‑window detectors: port scan, brute‑force, volumetric DDoS, bytes anomaly
- **Rules engine** (JSON) for declarative detections
- **NDJSON** input/output in addition to CSV + JSON
- **Multithreaded** pipeline (`--threads`), **sampling** (`--sample 1/N`), **per‑key memory caps**
- **Prometheus metrics** HTTP endpoint
- **SARIF 2.1.0** export
- **Plugin API** (dlopen/LoadLibrary) with example
- **Optional PCAP** support (libpcap)

## Build & Run
```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j

# CSV
./build/neonsec analyze --input examples/sample_logs.csv --format text
# NDJSON
./build/neonsec analyze --input examples/sample_logs.ndjson --input-format ndjson --format ndjson
# Rules
./build/neonsec analyze --input examples/sample_logs.csv --rules rules/example.json --format json
# Multithreaded
./build/neonsec analyze --input examples/sample_logs.csv --threads 4 --format json
```

## Validate mode
```bash
./build/neonsec validate --rules rules/example.json --input examples/sample_logs.csv --input-format csv
```

## Shell completions
- Bash: `source contrib/completions/neonsec.bash`
- Zsh:  `fpath+=(contrib/completions)` then `compinit`
- Fish: `source contrib/completions/neonsec.fish`

## Benchmarks
```bash
python3 bench/generate.py 200000 > /tmp/in.csv
./build/neonsec analyze --input /tmp/in.csv --format json >/dev/null
```
## Integrity
- Offline **SBOM** provided: `sbom.spdx`
- File checksums: `CHECKSUMS.sha256`
- Security contacts: `security.txt` and `site/.well-known/security.txt`

## C API (optional)
```bash
cmake -S . -B build -DNEONSEC_BUILD_C_API=ON
cmake --build build -j
gcc -Iinclude examples/c_api_example.c -Lbuild -lneonsec_c -Wl,-rpath,build -o c_api_example
./c_api_example
```

## Fuzzers (optional, clang + libFuzzer)
```bash
cmake -S . -B build -DNEONSEC_BUILD_FUZZERS=ON -DCMAKE_CXX_COMPILER=clang++ -DNEONSEC_BUILD_TESTS=OFF
cmake --build build -j
./build/fuzz_ndjson
./build/fuzz_csv
```

## Rules JSON Schema
A machine-readable schema is available at `schemas/rules.schema.json` for external validators.


## CI-friendly exits and quiet mode
- `--fail-on-findings`: exit code **3** if any finding was produced (useful for pipelines).
- `--quiet`: suppress parse errors to stderr.
- `--version` / `-v`: print version and exit.

## Deterministic ordering (optional)
For reproducible pipelines, use `--stable-order` to sort findings by (ts, type, key, details) and print at the end.
Note: this buffers findings in memory; prefer streaming mode for very large inputs.

## Redaction & output limiting
- `--redact` masks IPs/usernames in findings for safer logs.
- `--max-findings N` caps the number of printed findings; add `--fail-on-findings` to make pipelines fail on any.

## Privacy-preserving outputs
- `--pseudonymize` + `--pseudonymize-salt HEX`: replace IPs/usernames with stable tokens (e.g., `h:1a2b3c4d`) suitable for cross-run correlation without exposing PII.
- `--redact`: simpler masking (non-reversible). `--redact` and `--pseudonymize` are mutually exclusive.
- `--summary`: print a count per finding type at the end (to stderr).

Color auto-detection honors `NO_COLOR`. Use `--color` / `--no-color` to override.

## Output formats and time
- `--format yaml` prints per-finding YAML blocks.
- `--ts-format iso|epoch` controls timestamp rendering in text/yaml (JSON remains numeric epoch to preserve schema).
- `--tee FILE` duplicates output to a file while keeping stdout.

Reproducible builds: the CMake config detects `SOURCE_DATE_EPOCH` and uses `-ffile-prefix-map` when available.


## CSV dialect & stats
- `--csv-delim CH` / `--csv-quote CH` adjust the CSV parser.
- `--stats` prints processed records, findings, elapsed seconds and EPS.

## Syslog sink (POSIX)
- `--syslog [facility]` mirrors output to syslog (default LOG_USER; also supports `auth`, `daemon`).

## Env overrides (precedence: CLI > env > config)
- `NEONSEC_THREADS`, `NEONSEC_SAMPLE`, `NEONSEC_FORMAT`, `NEONSEC_TS_FORMAT`, `NEONSEC_COLOR`.


## Scale & reproducibility knobs
- `--max-records N`: stop after N input records (helps bound runtime for huge streams).
- `--dedupe`: suppress duplicate findings of the same `(type,key)` during a run.


## Additional output formats
- `--format stix`: emit a STIX 2.1-like bundle (offline).
- `--format html`: write a single-page HTML table for human review.

## Resource limits (POSIX)
- `--rlimit-mem MB`, `--rlimit-cpu SEC` to bound resource usage in batch jobs.

## Nix
Build with Nix: `nix build .#neonsec`


## Signals & generator
- Handles SIGINT/SIGTERM gracefully.
- `neonsec generate` emits synthetic records for testing.


## Run metadata & rotation
- `--run-id STR` or `NEONSEC_RUN_ID` to tag executions.
- `--prolog` outputs a first JSON line with `run_id`, timestamp and chosen format.
- `--tee-rotate-size MB` / `--tee-rotate-keep N` rotate the tee file to cap disk usage.

## Anti-spoofing
- We strip Unicode BiDi controls (e.g., LRE/RLE/RLO/FSI/PDI, LRM/RLM) from `key`/`details` upon emission.
- Combine with `--redact`/`--pseudonymize` for safer triage.

## Memory stats
- With `--stats`, we also report `maxrss_kb` (POSIX) for capacity planning.


## Baselines & suppressions
- `--baseline FILE` hides findings whose `(type,key)` already exist in a prior neonsec output (NDJSON or CSV). Ideal para "solo lo nuevo".
- `--suppress-file FILE` o `--suppress 'type:key'` aplican patrones con `*` y `?` (por ejemplo: `dns_*:*` o `*:10.0.*`).

## ASCII-only & anti-spoofing
- `--ascii-only` fuerza salida 7-bit segura para sistemas con parsers frágiles. Los controles BiDi se eliminan siempre.

## Epilogue digest
- Con `--epilogue` se añade una línea final JSON con `run_id`, `total` y `sha256` del stream emitido, útil para cadena de custodia.



## Time windows & selectors
- `--since EPOCH` / `--until EPOCH` to constrain the time-range.
- `--only-type/--skip-type`, `--only-key/--skip-key`, `--only-details/--skip-details` accept glob patterns (`*`, `?`) and are repeatable.


## CSV header & indexing
- `--csv-header` adds `ts,type,key,details` as the first line for CSV outputs.
- `--index-output FILE` writes byte offsets for each finding (from the beginning of the stream), useful for random-access.

## Suppression audit
- `--audit-suppressions FILE` produces a JSON object with total suppressed by baseline and by each `type:key` pattern.

## Flushing
- `--flush` forces per-record flush on stdout y tee (útil en pipelines con buffers grandes).


## Rate limiting & templating
- `--rate-limit RPS` throttles emission to RPS records/sec.
- `--text-template "..."` controls text output; placeholders: `{ts}`, `{type}`, `{key}`, `{details}`.

## Machine-readable summaries
- `--summary-json FILE` writes a JSON object with totals and per-type counts (and Top-N per type when `--summary-top N` is passed).


## Deduplication & signal shaping
- `--dedupe-window SEC` suppresses repeated `(type,key)` within `SEC` seconds.
- `--min-key-count N` keeps only `(type,key)` whose count in the run is `>= N` (forces stable order to ensure correctness).

## Time buckets
- `--bucket-summary FILE --bucket-size SEC` writes a JSON of totals per bucket and per type, useful for quick trend charts.


## Input validation & flexible redaction
- `--validate-input` turns on basic record validation (abort early with `--strict`).
- `--redact-patterns FILE` applies ECMAScript regexes (one per line) to `key` and `details`; change replacement with `--redact-repl`.

## HTML reporting & artifacts
- `--report-html FILE` produces a self-contained HTML summary (accessible, no external assets).
- `--artifact-dir DIR` packages run metadata and summary JSONs for handoff.

## PID files
- `--pidfile FILE` writes the process id and removes it on clean termination.


## Sampling
- `--sample-rate P` (0..1) keeps a fraction of findings; combine with `--sample-seed S` for reproducible sampling.

## Partitioned outputs
- `--split-output DIR --split-by type|key|ts [--split-bucket SEC]` writes per-partition files alongside normal stdout/tee output.

## Error budgets
- With `--validate-input`, use `--max-errors N` to stop early when input quality is poor.

## Self test
- `neonsec selftest` runs a basic in-binary verification of sanitization and redaction logic.

Accessibility: the HTML report adapts to light/dark modes and includes ARIA roles.


## Tamper-evident streams
- `--chain` produces a per-record SHA-256 chain; for NDJSON, a `"chain"` field is injected; for CSV, an extra `chain` column is added; for text, a `chain=<hex>` suffix.

## Newlines & tee mode
- `--newline lf|crlf` normalizes line endings; `--tee-mode append|truncate` controls how `--tee` is opened.

## IP masking
- `--ip-mask N` masks IPv4 addresses (supports 8/16/24) in `key` and `details` after sanitization and redaction.

## Markdown reports
- `--report-md FILE` creates a Markdown summary ready for wikis and repos.

## Grouped counts
- `--group-output FILE --group-by type|key` writes aggregated counts in JSON (uses internal summary maps).


## Record ids & byte budgets
- `--record-id [--record-id-start N]` injects a sequential `id` into JSON/NDJSON (`"id":N`), CSV (extra `id` column), and text (`id=N`).
- `--max-output-bytes N` guards downstream consumers by capping total emitted bytes.

## UTF-8 strictness
- `--utf8-strict` replaces invalid UTF-8 sequences in `key` and `details` with `?` after other sanitization steps.

## Error metrics
- `--errors-json FILE` summarizes invalid inputs and drop reasons (sampling, selectors, dedupe-window, min-key-count) plus whether output was truncated.


## HMAC signing
- `--hmac-secret "..."` or `--hmac-env VAR` appends an HMAC-SHA256 per record (`hmac` field/column/suffix), in addition to `--chain` if enabled.

## Output control
- `--out FILE [--atomic-out]` writes to a file atomically; keep using `--tee` if you also want a live copy.

## Limits and time control
- `--limit-findings N` caps the number of records.

- `--ts-offset SEC` shifts timestamps (affects printing and bucket summaries).

## Anomaly detection
- `--anomaly-zscore T --anomaly-window SEC --anomaly-output FILE` detects spikes via z-score over bucketed counts per type and writes a JSON list.


## Dry-run & diagnostics
- `--dry-run` runs the full pipeline without writing output bytes (good for QA and performance tests).
- `--out-digest FILE` records the SHA-256 of the emitted stream for provenance.
- `--log-level` and `--log-format` provide structured, thresholded diagnostics to stderr.


## PII presets
- `--pii-preset basic|strict` applies built-in patterns to `key` and `details` after sanitization/redaction:
  - **basic:** emails, phone numbers (loose), IPv6, MAC, and credit cards (validated with Luhn) → redacted tokens.
  - **strict:** adds SSN-like and IBAN-like masks.

## Time-based tee rotation
- `--tee-rotate-interval SEC` rotates the `--tee` file on a time schedule (works alongside size-based rotation).


## Sharding
- `--shard-count N --shard-index I [--shard-by key|type|id]` deterministically emits only the selected shard.

## Details truncation
- `--details-max N [--no-ellipsis]` truncates overly long `details` to protect privacy and control size.

## Utilities
- `neonsec digest --input FILE` prints the SHA-256 of a file.
- `neonsec verify-out --input FILE --format csv|ndjson|json|text [--hmac-secret SECRET]` recomputes HMAC per line/object (ignoring chain) and returns non-zero on mismatch.


## Bloom filter dedup
- `--bloom-bits N --bloom-hash-count K --bloom-key key|type|type+key|record [--bloom-state FILE]` provides memory-efficient duplicate suppression at scale.

## Transform explainability
- `--explain-transform` appends an `explain` attribute (JSON/NDJSON), a column (CSV), or a suffix (text) with the applied pipeline steps.

## Input digest
- `--input-digest-out FILE` writes the SHA-256 of the input file for provenance and run linking.

## Graceful termination
- Handles SIGINT/SIGTERM to stop accepting new records, persist Bloom state and metrics, and exit cleanly.


## Schema enforcement
- `--schema FILE` loads a minimal schema (key=value lines):  
  - `type.pattern=REGEX`, `type.deny=REGEX`, `key.pattern=REGEX`, `key.deny=REGEX`, `details.maxlen=N`  
- `--schema-enforce warn|strict` controls whether violations are tracked only or dropped.

## Per-key rate limit
- `--limit-key-rate N --limit-key-window SEC` drops excess records per key within the sliding window (tracked in `dropped.rate`).

## JSON pretty print
- `--json-indent N` pretty-prints when `--format json` is used.

## Profiling JSON
- `--profile-json FILE` outputs `wall_ms`, `processed`, `emitted`, `invalid`, and all drop metrics.
