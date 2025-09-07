
# Architecture
- Readers: CSV & NDJSON → `LogRecord` (no external deps).
- Sliding Window: time-bounded state & metrics for detectors.
- Detectors: port-scan, DDoS unique, brute-force.
- Plugins: shared libs via `neonsec_register(LogRecord, SlidingWindow, vector<Finding>&)`.
- Metrics Server: Prometheus text; `--metrics host:port`; optional TLS with OpenSSL.
- Pipeline: reader thread → bounded queue → workers; backpressure protects memory.
