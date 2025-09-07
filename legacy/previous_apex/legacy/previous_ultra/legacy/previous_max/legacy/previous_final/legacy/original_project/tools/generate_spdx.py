#!/usr/bin/env python3
# Generates a minimal SPDX 2.3 tag-value document listing project files and Apache-2.0 license.
import os, sys, time, hashlib
root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
files = []
for d,_,fns in os.walk(root):
    for fn in fns:
        p = os.path.join(d, fn)
        if ".git" in p: continue
        files.append(os.path.relpath(p, root))
print("SPDXVersion: SPDX-2.3")
print("DataLicense: CC0-1.0")
print("SPDXID: SPDXRef-DOCUMENT")
print("DocumentName: neonsec")
print("DocumentNamespace: http://spdx.org/spdxdocs/neonsec-%d" % int(time.time()))
for i, fp in enumerate(sorted(files)):
    h = hashlib.sha256(open(os.path.join(root, fp), "rb").read()).hexdigest()
    print("FileName: %s" % fp)
    print("SPDXID: SPDXRef-File-%d" % i)
    print("FileChecksum: SHA256: %s" % h)
    print("LicenseConcluded: Apache-2.0")
    print("LicenseInfoInFile: Apache-2.0")
    print("FileType: OTHER")
