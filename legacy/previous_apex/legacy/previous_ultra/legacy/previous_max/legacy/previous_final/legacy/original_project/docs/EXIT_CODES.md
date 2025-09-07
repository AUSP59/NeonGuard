# Exit Codes
- **0**: Success (no errors). If `--fail-on-findings` not set, findings do not affect exit code.
- **2**: Usage/config/input error (e.g., cannot open file, invalid rules).
- **3**: Findings were produced and `--fail-on-findings` is enabled.
