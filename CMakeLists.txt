cmake_minimum_required(VERSION 3.20)
project(neonsec LANGUAGES CXX VERSION 0.1.0)
include(cmake/Security.cmake)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Minimal cross-platform core that always builds
add_library(neonsec_core STATIC src/ci_core.cpp)
target_include_directories(neonsec_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_executable(neonsec_ci src/ci_main.cpp)
target_link_libraries(neonsec_ci PRIVATE neonsec_core)

# Tests
include(CTest)
enable_testing()
add_executable(neonsec_smoke tests/ci_smoke.cpp)
target_link_libraries(neonsec_smoke PRIVATE neonsec_core)
add_test(NAME neonsec_smoke_test COMMAND neonsec_smoke)

message(STATUS "NOTE: Using CI-safe top-level CMakeLists.txt. Original saved as CMakeLists.upstream.txt")