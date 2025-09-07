#!/usr/bin/env python3
import sys, os, re
SPDX = re.compile(rb"SPDX-License-Identifier:\s*Apache-2\.0")
fail = 0
for d,_,fs in os.walk("."):
    if ".git" in d or "build" in d: continue
    for f in fs:
        if not f.endswith((".cpp",".hpp",".h",".c",".py",".sh",".yml",".yaml",".md")): continue
        p=os.path.join(d,f)
        with open(p,"rb") as fh:
            data=fh.read(4096)
            if not SPDX.search(data):
                print("Missing SPDX header:", p)
                fail = 1
sys.exit(fail)
