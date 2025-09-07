.PHONY: all build test install package format sbom clean
all: build

build:
	cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
	cmake --build build -j

test:
	cmake -S . -B build -DNEONSEC_BUILD_TESTS=ON
	cmake --build build -j
	ctest --test-dir build --output-on-failure

install:
	cmake --install build --prefix /usr/local

package:
	cpack

format:
	clang-format -i $(shell git ls-files '*.cpp' '*.hpp')

sbom:
	python3 tools/generate_spdx.py > sbom.spdx

clean:
	rm -rf build

doctor:
	./build/neonsec doctor || true

verify:
	./build/neonsec verify
