# Config Validation (Optional)

A lightweight validator to catch common misconfigurations before deployment.

## Usage
```bash
python3 tools/validate_config.py path/to/config.json
# or (if you have PyYAML installed):
python3 tools/validate_config.py path/to/config.yaml
```
If successful, prints `Config OK`. Otherwise exits with an error message.