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

message(STATUS "Using CCF install at ${CCF_ROOT}")
set(CCF_DIR "${CCF_ROOT}")
include("${CCF_CMAKE_DIR}/ccf-targets.cmake")
include("${CCF_CMAKE_DIR}/preproject.cmake")

project(
  scitt_selective_disclosure
  VERSION 0.1.0
  LANGUAGES C CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# The Python extension module is a shared object, so every object that ends up
# inside it has to be position independent. That is all of this project's own
# code, so it is set once here rather than per target.
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

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

target_link_libraries(scitt_sd_core PUBLIC ccfcrypto)

target_compile_options(
  scitt_sd_core PRIVATE -Wall -Wextra -Werror -Wshadow -Wundef
)

# The in-memory API: every operation the demo performs, bytes in and bytes out,
# with no filesystem and no command line anywhere in it. The Python extension
# module is the only adapter over it.
add_library(
  scitt_sd_native STATIC
  ${CMAKE_CURRENT_SOURCE_DIR}/native/api.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/native/disclosure_set.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/native/identity.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/native/report_json.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/native/secrets.cpp
)
target_link_libraries(scitt_sd_native PUBLIC scitt_sd_core)
target_compile_options(
  scitt_sd_native PRIVATE -Wall -Wextra -Werror -Wshadow -Wundef
)

# --- the Python extension module ---------------------------------------------

# The in-process binding the web application imports. It is how the demo
# reaches the C++ core: no subprocess, no temporary files, no key material on
# any path.
#
# AUTO builds the module when a Python development installation is present and
# carries on when it is not, so that a machine with no Python headers (a
# C++-only CI job, say) still builds and tests everything else. ON requires it,
# and OFF never builds it.
set(BUILD_PYTHON_MODULE
    "AUTO"
    CACHE STRING "Build the _native Python extension module (ON, OFF or AUTO)"
)
set_property(CACHE BUILD_PYTHON_MODULE PROPERTY STRINGS ON OFF AUTO)

set(SCITT_SD_PYTHON_OUTPUT_DIR
    ""
    CACHE PATH
    "Where to place the built _native module. Empty places it in the build \
directory; a build that installs it beside a Python package points it there."
)

# Development.Module, not Development: an extension module must not link
# libpython, so that it loads into whichever interpreter imports it.
string(TOUPPER "${BUILD_PYTHON_MODULE}" SCITT_SD_PYTHON_MODULE_REQUEST)
set(SCITT_SD_PYTHON_MODULE OFF)
if(SCITT_SD_PYTHON_MODULE_REQUEST STREQUAL "AUTO")
  find_package(Python3 COMPONENTS Interpreter Development.Module QUIET)
  if(Python3_FOUND)
    set(SCITT_SD_PYTHON_MODULE ON)
  else()
    message(
      STATUS
      "No Python development installation was found: the _native module will "
      "not be built. Configure with -DBUILD_PYTHON_MODULE=ON to require it."
    )
  endif()
elseif(SCITT_SD_PYTHON_MODULE_REQUEST STREQUAL "ON")
  find_package(Python3 COMPONENTS Interpreter Development.Module REQUIRED)
  set(SCITT_SD_PYTHON_MODULE ON)
elseif(NOT SCITT_SD_PYTHON_MODULE_REQUEST STREQUAL "OFF")
  # Anything else is a typo, and silently treating it as one of the three
  # would build something other than what was asked for.
  message(
    FATAL_ERROR
    "BUILD_PYTHON_MODULE must be ON, OFF or AUTO, not "
    "'${BUILD_PYTHON_MODULE}'."
  )
endif()

if(SCITT_SD_PYTHON_MODULE)
  # A system pybind11 is used when one is installed; otherwise the pinned
  # release is fetched, as with CLI11 above and GoogleTest below.
  find_package(pybind11 CONFIG QUIET)
  if(NOT TARGET pybind11::module)
    include(FetchContent)
    FetchContent_Declare(
      pybind11
      GIT_REPOSITORY https://github.com/pybind/pybind11.git
      GIT_TAG v2.13.6
    )
    FetchContent_MakeAvailable(pybind11)
  endif()
  message(
    STATUS "Building _native for Python ${Python3_VERSION} (pybind11 "
           "${pybind11_VERSION})"
  )

  pybind11_add_module(
    scitt_sd_python_module MODULE
    ${CMAKE_CURRENT_SOURCE_DIR}/bindings/python_module.cpp
  )
  set_target_properties(
    scitt_sd_python_module PROPERTIES OUTPUT_NAME _native
  )
  target_link_libraries(scitt_sd_python_module PRIVATE scitt_sd_native)
  target_compile_definitions(
    scitt_sd_python_module PRIVATE SCITT_SD_VERSION="${PROJECT_VERSION}"
  )
  target_compile_options(
    scitt_sd_python_module PRIVATE -Wall -Wextra -Werror -Wshadow -Wundef
  )

  if(SCITT_SD_PYTHON_OUTPUT_DIR)
    file(MAKE_DIRECTORY "${SCITT_SD_PYTHON_OUTPUT_DIR}")
    set_target_properties(
      scitt_sd_python_module
      PROPERTIES LIBRARY_OUTPUT_DIRECTORY "${SCITT_SD_PYTHON_OUTPUT_DIR}"
    )
  endif()

  # Installed on its own (`cmake --install --component python`), separately
  # from the tool, for a build that wants the module packaged. The demo image
  # installs the tool only.
  install(
    TARGETS scitt_sd_python_module
    LIBRARY DESTINATION python COMPONENT python
  )
endif()

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

  file(GLOB NATIVE_TEST_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/tests/native/*.cpp)
  scitt_sd_require_sources(
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/native" NATIVE_TEST_SOURCES
  )
  add_executable(native_tests ${NATIVE_TEST_SOURCES})
  target_link_libraries(
    native_tests PRIVATE scitt_sd_native GTest::gtest GTest::gtest_main
  )
  target_compile_options(native_tests PRIVATE -Wall -Wextra -Werror -Wshadow)
  add_test(NAME native_tests COMMAND native_tests)

  # The extension module is exercised through the interpreter it was built
  # for: importing it and running the operations that stand on their own is
  # what proves the binding, rather than the library behind it. The bundle
  # flow needs a transparent statement a transparency service would return, so
  # native_tests owns that end of it.
  if(SCITT_SD_PYTHON_MODULE)
    add_test(
      NAME python_module_tests
      COMMAND
        ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/native/python_module_test.py
    )
    set_tests_properties(
      python_module_tests
      PROPERTIES
        ENVIRONMENT
        "PYTHONPATH=$<TARGET_FILE_DIR:scitt_sd_python_module>;PYTHONDONTWRITEBYTECODE=1"
    )
  endif()
endif()
