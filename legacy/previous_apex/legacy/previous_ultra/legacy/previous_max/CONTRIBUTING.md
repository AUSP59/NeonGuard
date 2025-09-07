
# Contributing

- Toolchain: CMake >= 3.20, C++20 compiler.
- Build: `cmake -S . -B build && cmake --build build -j`
- Tests: `ctest --test-dir build --output-on-failure`
- Style: `clang-format`, `clang-tidy` (see workflows)
- DCO: `git commit -s -m "..."`

Security reports: `SECURITY.md`
