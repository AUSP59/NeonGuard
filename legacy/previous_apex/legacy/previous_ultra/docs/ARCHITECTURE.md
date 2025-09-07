
# Architecture

- **Readers**: CSV & NDJSON to `LogRecord`.
- **Window**: time-bounded state for metrics.
- **Detectors**: port-scan & DDoS unique.
- **Plugins**: shared libraries via `neonsec_register` hook.
- **MetricsServer**: Prometheus text endpoint; bind host configurable.
- **Pipeline**: reader thread -> bounded queue -> worker pool; backpressure protects memory.
