
#!/usr/bin/env python3
import os, sys, shutil
REQUIRED = [
 "LICENSE","NOTICE","README.md","CMakeLists.txt","SBOM.cdx.json",
 "CODE_OF_CONDUCT.md","SECURITY.md","CONTRIBUTING.md","GOVERNANCE.md",
 "ETHICS.md","ACCESSIBILITY.md","INCLUSION.md","SUSTAINABILITY.md","COMPLIANCE.md",
 "docs/THREAT_MODEL.md","docs/ARCHITECTURE.md","man/neonsec.1"
]
def main():
    missing = [p for p in REQUIRED if not os.path.exists(p)]
    print("Missing:", missing)
    print("cmake:", shutil.which("cmake"))
    sys.exit(0 if not missing else 1)
if __name__ == "__main__":
    main()
