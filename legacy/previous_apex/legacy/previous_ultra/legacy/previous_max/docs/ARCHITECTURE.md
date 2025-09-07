
# Architecture

- **CSV/NDJSON Readers**: parse known fields into `LogRecord` (no external deps).
- **SlidingWindow**: time-bounded state; exposes metrics for detectors.
- **Detectors**: port-scan & DDoS-unique; easily extensible.
- **Plugins**: shared library hook `neonsec_register` returns a function to append findings.
- **MetricsServer**: HTTP endpoint (text format) for Prometheus scraping.
- **Pipeline**: reader thread -> bounded queue -> worker pool with backpressure.
