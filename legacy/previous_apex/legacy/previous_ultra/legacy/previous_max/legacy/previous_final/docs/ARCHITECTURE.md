
# Architecture

NeonSec processes CSV network logs into a sliding window and runs detectors:
- **SlidingWindow**: time-based queue updated per record.
- **Detectors**: port-scan & DDoS uniqueness thresholds.
- **Rules**: optional JSON thresholds loader.
- **Reporters**: text output (extensible).

Extensibility: add new detectors using the `Finding` type and include them in `main.cpp`.
