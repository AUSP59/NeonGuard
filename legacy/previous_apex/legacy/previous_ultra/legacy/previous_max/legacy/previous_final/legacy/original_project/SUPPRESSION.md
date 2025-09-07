
# Suppression Patterns
Each line is `type:key` with glob wildcards `*` and `?`. Examples:
- `portscan:*` suppresses all portscan findings.
- `*:10.0.*` suppresses any key starting with `10.0.`.
- `dns_*:*.corp.local` combines both sides.
Lines starting with `#` are comments. Use `--suppress-file FILE` or pass `--suppress 'pattern'` multiple times.
