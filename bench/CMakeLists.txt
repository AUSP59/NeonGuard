cmake_minimum_required(VERSION 3.16)
project(neonsec_bench CXX)

add_executable(bench_neonsec runner.cpp)
target_compile_features(bench_neonsec PRIVATE cxx_std_20)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
  target_compile_options(bench_neonsec PRIVATE -O3 -DNDEBUG -march=native)
endif()