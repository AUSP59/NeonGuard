
# Release Verification

1. Check tag signature (if provided) and commit sign-offs (DCO).
2. Verify SBOM (`SBOM.cdx.json`) presence.
3. Build from source: `cmake -S . -B build && cmake --build build`.
4. Run tests: `ctest`.
5. Run example & check `/metrics` endpoint.
