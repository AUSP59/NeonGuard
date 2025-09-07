cmake_minimum_required(VERSION 3.23)
project(neonsec VERSION 1.3.0 LANGUAGES CXX)

option(NEONSEC_BUILD_TESTS "Build tests" OFF)
option(NEONSEC_ENABLE_LTO "Enable LTO/ThinLTO in Release" ON)
option(NEONSEC_ENABLE_SANITIZERS "Enable ASan/UBSan for debug/test" OFF)
option(NEONSEC_WITH_PCAP "Enable PCAP input" OFF)
option(NEONSEC_STRICT "Treat warnings as errors" ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Warnings
if(MSVC)
  add_compile_options(/W4 /permissive-)
  if(NEONSEC_STRICT) add_compile_options(/WX) endif()
else()
  add_compile_options(-Wall -Wextra -Wpedantic)
  if(NEONSEC_STRICT) add_compile_options(-Werror) endif()
endif()

# LTO
if(CMAKE_BUILD_TYPE STREQUAL "Release" AND NEONSEC_ENABLE_LTO)
  include(CheckIPOSupported)
  check_ipo_supported(RESULT ipo_supported OUTPUT ipo_output)
  if(ipo_supported) set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON) endif()
endif()

# Sanitizers
if(NEONSEC_ENABLE_SANITIZERS AND NOT MSVC)
  add_compile_options(-fsanitize=address,undefined)
  add_link_options(-fsanitize=address,undefined)
endif()

# Hardening (non-Windows)
if(NOT MSVC)
  add_compile_options(-fstack-protector-strong -D_FORTIFY_SOURCE=2)
endif()

# Optional PCAP
if(NEONSEC_WITH_PCAP)
  find_package(PCAP REQUIRED)
  add_compile_definitions(NEONSEC_WITH_PCAP=1)
endif()

option(NEONSEC_BUILD_SHARED "Build neonsec as a shared library" OFF)
add_library(neonsec $<IF:$<BOOL:${NEONSEC_BUILD_SHARED}>,SHARED,STATIC>
  src/log_record.cpp src/json_line.cpp src/csv_reader.cpp src/sliding_window.cpp
  src/detectors.cpp src/rules.cpp src/reporters.cpp src/plugin.cpp src/config.cpp
  src/metrics_server.cpp src/sarif.cpp
  $<IF:$<BOOL:${NEONSEC_WITH_PCAP}>,src/pcap_input.cpp,>
)
target_include_directories(neonsec PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>)
if(NEONSEC_WITH_PCAP) target_link_libraries(neonsec PRIVATE PCAP::PCAP) endif()
target_compile_definitions(neonsec PUBLIC NEONSEC_VERSION="${PROJECT_VERSION}")
set_target_properties(neonsec PROPERTIES POSITION_INDEPENDENT_CODE ON)

add_executable(neonsec_cli src/main.cpp)
target_link_libraries(neonsec_cli PRIVATE neonsec)
set_target_properties(neonsec_cli PROPERTIES OUTPUT_NAME neonsec)

include(GNUInstallDirs)
install(TARGETS neonsec neonsec_cli
  EXPORT neonsecTargets
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT neonsecTargets FILE neonsecTargets.cmake NAMESPACE neonsec:: DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/neonsec)

# pkg-config
file(WRITE ${CMAKE_BINARY_DIR}/neonsec.pc
"prefix=${CMAKE_INSTALL_PREFIX}
exec_prefix=${CMAKE_INSTALL_PREFIX}
libdir=${CMAKE_INSTALL_FULL_LIBDIR}
includedir=${CMAKE_INSTALL_FULL_INCLUDEDIR}
Name: neonsec
Description: Neon Secure Network System core library
Version: ${PROJECT_VERSION}
Libs: -L${CMAKE_INSTALL_FULL_LIBDIR} -lneonsec
Cflags: -I${CMAKE_INSTALL_FULL_INCLUDEDIR}
")
install(FILES ${CMAKE_BINARY_DIR}/neonsec.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

# Tests
if(NEONSEC_BUILD_TESTS)
  enable_testing()
  add_executable(neonsec_tests tests/tests.cpp)
  target_link_libraries(neonsec_tests PRIVATE neonsec)
  add_test(NAME neonsec_basic COMMAND neonsec_tests)
endif()

# CPack packaging (TGZ/ZIP)
include(CPack)
set(CPACK_PACKAGE_NAME "neonsec")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_GENERATOR "TGZ;ZIP")

# Man page and completions
include(GNUInstallDirs)
install(FILES docs/neonsec.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)
install(FILES contrib/completions/neonsec.bash DESTINATION ${CMAKE_INSTALL_DATADIR}/bash-completion/completions RENAME neonsec)
install(FILES contrib/completions/neonsec.zsh DESTINATION ${CMAKE_INSTALL_DATADIR}/zsh/site-functions RENAME _neonsec)
install(FILES contrib/completions/neonsec.fish DESTINATION ${CMAKE_INSTALL_DATADIR}/fish/vendor_completions.d RENAME neonsec.fish)

option(NEONSEC_BUILD_C_API "Build C API shared library" ON)
if(NEONSEC_BUILD_C_API)
  add_library(neonsec_c SHARED src/c_api.cpp)
  set_target_properties(neonsec_c PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION 1)
  target_compile_definitions(neonsec_c PRIVATE NEONSEC_CAPI_EXPORTS)
  target_include_directories(neonsec_c PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
  target_link_libraries(neonsec_c PRIVATE neonsec)
  set_target_properties(neonsec_c PROPERTIES OUTPUT_NAME neonsec_c)
  install(TARGETS neonsec_c RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()

option(NEONSEC_BUILD_FUZZERS "Build libFuzzer targets (clang only)" OFF)
if(NEONSEC_BUILD_FUZZERS)
  add_subdirectory(fuzz)
endif()

set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN ON)

# pkg-config for C API
file(WRITE ${CMAKE_BINARY_DIR}/neonsec_c.pc
"prefix=${CMAKE_INSTALL_PREFIX}
exec_prefix=${CMAKE_INSTALL_PREFIX}
libdir=${CMAKE_INSTALL_FULL_LIBDIR}
includedir=${CMAKE_INSTALL_FULL_INCLUDEDIR}
Name: neonsec_c
Description: Neon Secure Network C API
Version: ${PROJECT_VERSION}
Libs: -L${CMAKE_INSTALL_FULL_LIBDIR} -lneonsec_c
Cflags: -I${CMAKE_INSTALL_FULL_INCLUDEDIR}
")
install(FILES ${CMAKE_BINARY_DIR}/neonsec_c.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)


option(NEONSEC_REPRO_BUILD "Apply reproducible build tweaks" ON)
if(NEONSEC_REPRO_BUILD)
  if(NOT MSVC)
    add_compile_options(-ffile-prefix-map=${CMAKE_SOURCE_DIR}=.)
  endif()
  if(DEFINED ENV{SOURCE_DATE_EPOCH})
    add_definitions(-DNEONSEC_SOURCE_DATE_EPOCH=$ENV{SOURCE_DATE_EPOCH})
  endif()
endif()


option(NEONSEC_STRIP "Strip binaries on install if possible" OFF)
if(NEONSEC_STRIP AND NOT MSVC)
  find_program(STRIP_BIN strip)
  if(STRIP_BIN)
    install(CODE "execute_process(COMMAND ${STRIP_BIN} ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR}/neonsec || true)")
  endif()
endif()


# CPack package metadata (DEB/RPM in addition to TGZ/ZIP)
set(CPACK_PACKAGE_NAME "neonsec")
set(CPACK_PACKAGE_VENDOR "NeonSec Project")
set(CPACK_PACKAGE_CONTACT "security@neonsec.org")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Neon Secure Network System")
set(CPACK_DEBIAN_PACKAGE_SECTION "utils")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "NeonSec Maintainers")
set(CPACK_RPM_PACKAGE_LICENSE "Apache-2.0")
set(CPACK_GENERATOR "TGZ;ZIP;DEB;RPM")
include(CPack)


option(NEONSEC_HARDEN "Enable hardening flags" ON)
if(NEONSEC_HARDEN)
  if(MSVC)
    add_compile_options(/GS /guard:cf /Qspectre)
    add_link_options(/DYNAMICBASE /NXCOMPAT)
  else()
    add_compile_options(-O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE)
    add_link_options(-Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -pie)
  endif()
endif()

# CMake package config (export targets)
install(TARGETS neonsec EXPORT neonsecTargets
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT neonsecTargets NAMESPACE neonsec:: DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/neonsec)
file(WRITE ${CMAKE_BINARY_DIR}/neonsecConfig.cmake "include(\"${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/cmake/neonsec/neonsecTargets.cmake\")")
file(WRITE ${CMAKE_BINARY_DIR}/neonsecConfigVersion.cmake "set(PACKAGE_VERSION \"${PROJECT_VERSION}\")")
install(FILES ${CMAKE_BINARY_DIR}/neonsecConfig.cmake ${CMAKE_BINARY_DIR}/neonsecConfigVersion.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/neonsec)
