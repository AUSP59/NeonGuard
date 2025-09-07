#!/usr/bin/env python3
import os, json, hashlib, time, sys
root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
components = []
for d,_,fns in os.walk(root):
    for fn in fns:
        p = os.path.join(d, fn)
        if '.git' in p: continue
        with open(p,'rb') as f: h = hashlib.sha256(f.read()).hexdigest()
        components.append({
            "type": "file",
            "name": os.path.relpath(p, root),
            "hashes": [{"alg":"SHA-256","content":h}],
            "licenses": [{"license": {"id": "Apache-2.0"}}]
        })
bom = {
  "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
  "metadata": {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
  "components": components
}
print(json.dumps(bom, indent=2))
