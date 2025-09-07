
cmake_minimum_required(VERSION 3.20)
project(neonsec VERSION 1.0.0 LANGUAGES CXX)

option(NEONSEC_BUILD_TESTS "Build tests" ON)
option(NEONSEC_ENABLE_LTO "Enable LTO" ON)
option(NEONSEC_ENABLE_ASAN "Enable AddressSanitizer (Debug)" OFF)
option(NEONSEC_ENABLE_UBSAN "Enable UBSan (Debug)" OFF)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if (MSVC)
  add_compile_options(/W4 /permissive- /Zc:preprocessor /Zc:__cplusplus)
else()
  add_compile_options(-Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow -Wformat=2 -Werror=format-security)
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

add_library(neonsec_core
  src/log.cpp
  src/csv_reader.cpp
  src/window.cpp
  src/detectors.cpp
  src/rules.cpp
  src/reporters.cpp
)

target_include_directories(neonsec_core PUBLIC include)

if (NEONSEC_ENABLE_LTO AND lto_supported)
  set_property(TARGET neonsec_core PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
endif()

add_executable(neonsec src/main.cpp)
target_link_libraries(neonsec PRIVATE neonsec_core)
if (NEONSEC_ENABLE_LTO AND lto_supported)
  set_property(TARGET neonsec PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
endif()

include(GNUInstallDirs)
install(TARGETS neonsec RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/neonsec FILES_MATCHING PATTERN "*.hpp")

if (NEONSEC_BUILD_TESTS)
  enable_testing()
  add_executable(neonsec_tests
    tests/test_csv.cpp
    tests/test_detectors.cpp
  )
  target_link_libraries(neonsec_tests PRIVATE neonsec_core)
  add_test(NAME neonsec_unit_tests COMMAND neonsec_tests)
endif()

include(CPack)
set(CPACK_PACKAGE_NAME "neonsec")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_GENERATOR "TGZ;ZIP")
