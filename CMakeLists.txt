# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.21)

# CCF must be found before project(): its preproject.cmake selects clang and a
# default build type, and CMake only honours that before the languages are
# enabled.
#
# ccf-config.cmake hard-codes CCF_DIR to /opt/ccf, so it only works for an
# install at that path. The package is located first, and a relocated (staged)
# install falls back to the target and preproject files, which are both
# relocatable.
find_file(
  CCF_TARGETS_FILE ccf-targets.cmake
  HINTS ${CMAKE_PREFIX_PATH} ENV CMAKE_PREFIX_PATH
  PATHS /opt/ccf
  PATH_SUFFIXES cmake
  DOC "CCF's imported target definitions"
)
if(NOT CCF_TARGETS_FILE)
  message(
    FATAL_ERROR
    "CCF was not found. Pass -DCMAKE_PREFIX_PATH=<ccf install prefix>."
  )
endif()

get_filename_component(CCF_CMAKE_DIR "${CCF_TARGETS_FILE}" DIRECTORY)
get_filename_component(CCF_ROOT "${CCF_CMAKE_DIR}" DIRECTORY)

if(CCF_ROOT STREQUAL "/opt/ccf")
  find_package(ccf REQUIRED)
else()
  message(STATUS "Using relocated CCF install at ${CCF_ROOT}")
  set(CCF_DIR "${CCF_ROOT}")
  include("${CCF_CMAKE_DIR}/ccf-targets.cmake")
  include("${CCF_CMAKE_DIR}/preproject.cmake")
endif()

project(
  scitt_selective_disclosure
  VERSION 0.1.0
  LANGUAGES C CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ccfcrypto names libcose_rs.a by absolute /opt/ccf path, which a relocated
# install does not have. The interface is rewritten to the located prefix.
get_target_property(_ccfcrypto_libs ccfcrypto INTERFACE_LINK_LIBRARIES)
string(
  REPLACE "/opt/ccf/lib/" "${CCF_ROOT}/lib/" _ccfcrypto_libs
          "${_ccfcrypto_libs}"
)
set_target_properties(
  ccfcrypto PROPERTIES INTERFACE_LINK_LIBRARIES "${_ccfcrypto_libs}"
)

set(CCF_INCLUDE_ROOT
    "${CCF_ROOT}"
    CACHE PATH "Root of the CCF include tree"
)

# The core library: CBOR/COSE/SD-CWT construction, the SCITT X.509 report
# profile, proof bundles and verification. CBOR goes exclusively through CCF's
# EverCBOR-backed ccf::cbor (ccf/_private/crypto/cbor.h, symbols in ccfcrypto)
# and cryptography exclusively through the CCF crypto APIs, so nothing is
# vendored here.
add_library(
  scitt_sd_core STATIC
  ${CMAKE_CURRENT_SOURCE_DIR}/core/cbor_value.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/core/cose.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/core/sd_cwt.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/core/profile.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/core/text_chunks.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/core/report.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/core/bundle.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/core/verify.cpp
)

# Sources include their own headers as "core/...", so the repository root is the
# include root.
target_include_directories(
  scitt_sd_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
)

# The imported CCF targets only carry a subset of the include tree (ccfcrypto
# exposes its quickjs 3rdparty include only), so the CCF headers, including the
# CCF-distributed didx509cpp used for did:x509 policy checks, are added
# explicitly. SYSTEM keeps CCF's own warnings out of this build.
target_include_directories(
  scitt_sd_core SYSTEM
  PUBLIC ${CCF_INCLUDE_ROOT}/include ${CCF_INCLUDE_ROOT}/include/ccf
         ${CCF_INCLUDE_ROOT}/include/3rdparty
)

target_link_libraries(scitt_sd_core PUBLIC ccfcrypto ccf)

target_compile_options(
  scitt_sd_core PRIVATE -Wall -Wextra -Werror -Wshadow -Wundef
)

option(BUILD_TESTS "Build the host-side C++ unit tests" OFF)

if(BUILD_TESTS)
  enable_testing()

  # A system GoogleTest is used when one is installed; otherwise the pinned
  # release is fetched, as the prototype did.
  find_package(GTest QUIET)
  if(NOT TARGET GTest::gtest)
    include(FetchContent)
    set(INSTALL_GTEST OFF)
    FetchContent_Declare(
      googletest
      GIT_REPOSITORY https://github.com/google/googletest.git
      GIT_TAG release-1.12.1
    )
    FetchContent_MakeAvailable(googletest)
  endif()

  # add_executable's own "No SOURCES given to target" is reported at generate
  # time and does not say which directory was empty, so an empty glob is
  # diagnosed here instead.
  function(scitt_sd_require_sources directory sources)
    if(NOT ${sources})
      message(
        FATAL_ERROR
        "BUILD_TESTS is ON but ${directory} contains no .cpp sources. Add at "
        "least one test source, or configure with -DBUILD_TESTS=OFF."
      )
    endif()
  endfunction()

  file(GLOB CORE_TEST_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/tests/core/*.cpp)
  scitt_sd_require_sources(
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/core" CORE_TEST_SOURCES
  )
  add_executable(core_tests ${CORE_TEST_SOURCES})
  target_link_libraries(
    core_tests PRIVATE scitt_sd_core GTest::gtest GTest::gtest_main
  )
  target_compile_options(core_tests PRIVATE -Wall -Wextra -Werror -Wshadow)
  add_test(NAME core_tests COMMAND core_tests)
endif()
