
# Reproducible Builds
We aim for deterministic outputs when `SOURCE_DATE_EPOCH` is set.
- Paths are normalized via `-ffile-prefix-map` where supported.
- Avoid non-deterministic macros (`__DATE__`, `__TIME__`) in sources.
