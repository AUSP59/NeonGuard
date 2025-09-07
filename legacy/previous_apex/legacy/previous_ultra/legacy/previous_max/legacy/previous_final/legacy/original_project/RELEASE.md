# Release Process (offline)
1. Update version in CMake and CHANGELOG.
2. `make package` to build TGZ/ZIP/DEB/RPM via CPack.
3. Generate SBOMs: `make sbom` and `python3 tools/generate_cyclonedx.py > bom.cdx.json`.
4. Verify integrity: `./build/neonsec verify` and compare `CHECKSUMS.sha256`.
