
# Contributing

- Toolchain: CMake >= 3.20, C++20 compiler.
- Build: `cmake -S . -B build && cmake --build build -j`
- Tests: `ctest --test-dir build --output-on-failure`
- Style: `clang-format`, `clang-tidy`, `cppcheck` (CI enforces format; tidy/cppcheck advisory)
- DCO: `git commit -s -m "..."`
- Security reports: `SECURITY.md`
