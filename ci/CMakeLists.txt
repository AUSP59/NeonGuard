cmake_minimum_required(VERSION 3.20)
project(neonsec_ci LANGUAGES CXX VERSION 0.1.3)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(neonsec_core STATIC src/core.cpp)
target_include_directories(neonsec_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_executable(neonsec_ci src/main.cpp)
target_link_libraries(neonsec_ci PRIVATE neonsec_core)

include(CTest)
enable_testing()
add_executable(neonsec_smoke tests/smoke.cpp)
target_link_libraries(neonsec_smoke PRIVATE neonsec_core)
add_test(NAME neonsec_smoke_test COMMAND neonsec_smoke)