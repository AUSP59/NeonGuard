
cmake_minimum_required(VERSION 3.20)
project(neonsec VERSION 4.0.0 LANGUAGES CXX)

option(NEONSEC_BUILD_TESTS "Build tests" ON)
option(NEONSEC_ENABLE_LTO "Enable LTO" ON)
option(NEONSEC_ENABLE_ASAN "Enable AddressSanitizer (Debug)" OFF)
option(NEONSEC_ENABLE_UBSAN "Enable UBSan (Debug)" OFF)
option(NEONSEC_WITH_PLUGINS "Build example plugins" ON)
option(NEONSEC_WITH_FUZZERS "Build libFuzzer targets (Clang/Linux)" OFF)
option(NEONSEC_WITH_PCAP "Build optional PCAP plugin" OFF)
option(NEONSEC_WITH_TLS "Enable TLS (OpenSSL) for metrics server" OFF)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if (MSVC)
  add_compile_options(/W4 /permissive- /Zc:preprocessor /Zc:__cplusplus)
else()
  add_compile_options(-Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow -Wformat=2 -Werror=format-security)
  add_compile_options(-fstack-protector-strong -D_FORTIFY_SOURCE=2)
  add_link_options(-Wl,-z,relro,-z,now)
endif()

if (NOT MSVC)
  if (NEONSEC_ENABLE_ASAN)
    add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address)
  endif()
  if (NEONSEC_ENABLE_UBSAN)
    add_compile_options(-fsanitize=undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=undefined)
  endif()
endif()

include(CheckIPOSupported)
if (NEONSEC_ENABLE_LTO)
  check_ipo_supported(RESULT lto_supported OUTPUT lto_out)
  if (lto_supported)
    message(STATUS "LTO enabled for Release.")
  else()
    message(STATUS "LTO not supported: ${lto_out}")
  endif()
endif()

if (NEONSEC_WITH_TLS)
  find_package(OpenSSL REQUIRED)
endif()

add_library(neonsec_core
  src/log.cpp
  src/csv_reader.cpp
  src/ndjson_reader.cpp
  src/window.cpp
  src/detectors.cpp
  src/rules.cpp
  src/reporters.cpp
  src/metrics_server.cpp
  src/plugin_loader.cpp
  src/bounded_queue.cpp
)

target_include_directories(neonsec_core PUBLIC include)
if (NEONSEC_WITH_TLS)
  target_compile_definitions(neonsec_core PUBLIC NEONSEC_WITH_TLS=1)
  target_link_libraries(neonsec_core PUBLIC OpenSSL::SSL OpenSSL::Crypto)
endif()

if (NEONSEC_ENABLE_LTO AND lto_supported)
  set_property(TARGET neonsec_core PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
endif()

add_executable(neonsec src/main.cpp)
target_link_libraries(neonsec PRIVATE neonsec_core)
if (NEONSEC_ENABLE_LTO AND lto_supported)
  set_property(TARGET neonsec PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
endif()

if (NEONSEC_WITH_PLUGINS)
  add_library(neonsec_example_plugin SHARED plugins/example_port50_block/plugin.cpp)
  target_include_directories(neonsec_example_plugin PUBLIC include)
  set_target_properties(neonsec_example_plugin PROPERTIES OUTPUT_NAME "neonsec_example")
endif()

if (NEONSEC_WITH_PCAP AND NOT MSVC)
  find_library(PCAP_LIB pcap)
  if (PCAP_LIB)
    add_library(neonsec_pcap SHARED plugins/pcap_ingest/plugin_pcap.cpp)
    target_include_directories(neonsec_pcap PUBLIC include)
    target_link_libraries(neonsec_pcap PRIVATE ${PCAP_LIB})
    set_target_properties(neonsec_pcap PROPERTIES OUTPUT_NAME "neonsec_pcap")
  else()
    message(WARNING "libpcap not found; PCAP plugin will not be built.")
  endif()
endif()

if (NEONSEC_WITH_FUZZERS AND NOT MSVC)
  add_executable(fuzz_ndjson fuzz/fuzz_ndjson.cpp)
  target_include_directories(fuzz_ndjson PRIVATE include)
  target_link_libraries(fuzz_ndjson PRIVATE neonsec_core)
  target_compile_options(fuzz_ndjson PRIVATE -fsanitize=fuzzer,address,undefined)
  target_link_options(fuzz_ndjson PRIVATE -fsanitize=fuzzer,address,undefined)
endif()

include(GNUInstallDirs)
install(TARGETS neonsec RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/neonsec FILES_MATCHING PATTERN "*.hpp")

if (NEONSEC_BUILD_TESTS)
  enable_testing()
  add_executable(neonsec_tests
    tests/test_csv.cpp
    tests/test_ndjson.cpp
    tests/test_detectors.cpp
  )
  target_link_libraries(neonsec_tests PRIVATE neonsec_core)
  add_test(NAME neonsec_unit_tests COMMAND neonsec_tests)
endif()

# CPack packaging (adds DEB/RPM)
include(CPack)
set(CPACK_PACKAGE_NAME "neonsec")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_GENERATOR "TGZ;ZIP;DEB;RPM")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "NeonSec Contributors")
set(CPACK_RPM_PACKAGE_LICENSE "Apache-2.0")
