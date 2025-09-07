# cmake/Security.cmake - Hardening, Sanitizers, Coverage, and LTO (opt-in/opt-out)

option(NEONSEC_HARDENED "Enable hardening flags (stack protector, RELRO/Now, PIE, Fortify)" ON)
option(NEONSEC_ENABLE_SANITIZERS "Enable Address/Undefined Behavior sanitizers" OFF)
option(NEONSEC_ENABLE_LTO "Enable Link-Time Optimization in Release/RelWithDebInfo" ON)
option(ENABLE_COVERAGE "Enable coverage flags for GCC/Clang" OFF)
option(NEONSEC_ENABLE_BENCH "Build optional bench targets" OFF)

include(CheckIPOSupported)
check_ipo_supported(RESULT IPO_SUPPORTED OUTPUT IPO_ERROR)

if (CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU" AND NOT MSVC)
  if(NEONSEC_HARDENED)
    add_compile_options(-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=3 -fPIE -fno-omit-frame-pointer)
    add_link_options(-Wl,-z,relro -Wl,-z,now -pie)
  endif()

  if(NEONSEC_ENABLE_SANITIZERS)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
  endif()

  if(ENABLE_COVERAGE AND CMAKE_BUILD_TYPE MATCHES "Coverage|Debug")
    add_compile_options(--coverage -fprofile-arcs -ftest-coverage)
    add_link_options(--coverage -fprofile-arcs -ftest-coverage)
  endif()
endif()

if(NEONSEC_ENABLE_LTO AND IPO_SUPPORTED AND CMAKE_BUILD_TYPE MATCHES "Release|RelWithDebInfo")
  set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
endif()

if(NEONSEC_ENABLE_BENCH AND EXISTS "${CMAKE_SOURCE_DIR}/bench/CMakeLists.txt")
  message(STATUS "Enabling bench targets (NEONSEC_ENABLE_BENCH=ON)")
  add_subdirectory(${CMAKE_SOURCE_DIR}/bench)
endif()