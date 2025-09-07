#!/usr/bin/env python3
# Lightweight config validator scaffold.
# Supports JSON by default; YAML if PyYAML is installed.

import sys, json, os

REQUIRED_KEYS = {
    "inputs": list,
    "detectors": list,
    "metrics": dict,
}

def load_config(path: str):
    ext = os.path.splitext(path)[1].lower()
    if ext in (".json",):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    if ext in (".yml", ".yaml"):
        try:
            import yaml  # type: ignore
        except Exception as e:
            raise SystemExit(f"YAML support requires PyYAML: {e}")
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    raise SystemExit(f"Unsupported config format: {ext}")

def main():
    if len(sys.argv) != 2:
        print("Usage: validate_config.py <config.json|yaml>")
        sys.exit(2)
    cfg = load_config(sys.argv[1])
    if not isinstance(cfg, dict):
        raise SystemExit("Config must be an object/dict.")
    for k, t in REQUIRED_KEYS.items():
        if k not in cfg:
            raise SystemExit(f"Missing required key: {k}")
        if not isinstance(cfg[k], t):
            raise SystemExit(f"Key '{k}' must be of type {t.__name__}")
    print("Config OK")

if __name__ == "__main__":
    main()