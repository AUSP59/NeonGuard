
# NeonSec OSS

A production-grade, zero-dependency C++20 network log analyzer with real code, tests, CI, container, governance, and security docs.

## Features
- C++20 + CMake with strict warnings and optional ASan/UBSan
- Sliding-window detectors (port-scan, DDoS uniqueness)
- CSV ingestion with simple schema
- Unit tests via `ctest`
- GitHub Actions CI + CodeQL
- Dockerfile (distroless runtime), devcontainer
- Apache-2.0 license, NOTICE, DCO, CODEOWNERS
- Security policy, governance, whitepaper, threat model, audit checklist
- SBOM (CycloneDX)

## Quick Start
```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release -j
./build/neonsec analyze --input examples/sample.csv --window 60
```

## Input CSV
Header:
```
ts,src_ip,dst_ip,src_port,dst_port,action,status,bytes,username
```

## Example
```
mkdir -p examples
cat > examples/sample.csv <<EOF
ts,src_ip,dst_ip,src_port,dst_port,action,status,bytes,username
1725499200,1.1.1.1,2.2.2.2,1000,80,connect,ok,10,-
1725499201,1.1.1.1,2.2.2.2,1000,81,connect,ok,10,-
1725499202,1.1.1.1,2.2.2.2,1000,82,connect,ok,10,-
1725499203,3.3.3.3,9.9.9.9,1000,80,connect,ok,1,-
1725499204,4.4.4.4,9.9.9.9,1000,80,connect,ok,1,-
EOF
./build/neonsec analyze --input examples/sample.csv --window 60
```

See `docs/` for architecture, security, threat model, and governance.
