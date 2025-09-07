# Operations Runbook

## Common commands
- Dry-run on a huge CSV: `neonsec analyze --input big.csv --dry-run --summary --stats --progress 50000`
- Tamper-evident logs: `neonsec analyze --input - --format ndjson --hash-output --prolog --run-id $(date +%s)`
- Rotate tee file at 100MB, keep 10: `--tee output.ndjson --tee-rotate-size 100 --tee-rotate-keep 10`

## Incident triage
1. Run with `--redact` or `--pseudonymize --pseudonymize-salt ...`.
2. Export metrics with `--metrics :9464` and watch cardinality; use `--dedupe` if needed.
3. Archive findings with `--hash-output` and verify integrity via `neonsec verify`.
