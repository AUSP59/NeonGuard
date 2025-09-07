
# Contributing

Thanks for your interest in NeonSec!

## Getting Started
- Toolchain: CMake >= 3.20, a C++20 compiler.
- Build: `cmake -S . -B build && cmake --build build -j`

## Tests
- Run `ctest --test-dir build --output-on-failure`

## Style
- `clang-format` per `.clang-format`
- `clang-tidy` per `.clang-tidy`

## DCO
All commits require sign-off: `git commit -s -m "feat: ..."`

## Security
Please read `SECURITY.md` for reporting vulnerabilities.
