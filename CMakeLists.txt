#[[
   Copyright 2022 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
]]

cmake_minimum_required(VERSION 3.19.0)

if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/third_party/evmone/evmone/evmc/.git)
  message(FATAL_ERROR "Git submodules not initialized, execute:\n  git submodule update --init --recursive")
endif()

get_directory_property(SILKWORM_HAS_PARENT PARENT_DIRECTORY)
if(NOT SILKWORM_HAS_PARENT)
  include(third_party/evmone/evmone/cmake/cable/bootstrap.cmake)
  include(CableBuildType)
  cable_set_build_type(DEFAULT Release CONFIGURATION_TYPES Release Debug)

  if(NOT CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE
        ${CMAKE_CURRENT_SOURCE_DIR}/cmake/toolchain/cxx20.cmake
        CACHE FILEPATH "" FORCE
    )
    include("${CMAKE_TOOLCHAIN_FILE}")
  endif()
endif()

project(silkworm)
set(PROJECT_VERSION 0.1.0-dev)

include(CableBuildInfo)

string(REGEX MATCH "([0-9]+)\\.([0-9]+)\\.([0-9]+)" _ ${PROJECT_VERSION})
set(PROJECT_VERSION_MAJOR ${CMAKE_MATCH_1})
set(PROJECT_VERSION_MINOR ${CMAKE_MATCH_2})
set(PROJECT_VERSION_PATCH ${CMAKE_MATCH_3})

cable_add_buildinfo_library(PROJECT_NAME ${PROJECT_NAME})

option(SILKWORM_WASM_API "Build WebAssembly API" OFF)
option(SILKWORM_CORE_ONLY "Only build Silkworm Core" OFF)
option(SILKWORM_CORE_USE_ABSEIL "Allow use of Abseil in Silkworm Core" ON)
option(SILKWORM_CLANG_COVERAGE "Clang instrumentation for code coverage reports" OFF)
option(SILKWORM_CLANG_TIDY "Clang-Tidy linter" OFF)
option(SILKWORM_SANITIZE "Build instrumentation for sanitizers" OFF)
option(SILKWORM_USE_MIMALLOC "Enable using mimalloc for dynamic memory management" ON)

if(NOT SILKWORM_HAS_PARENT)
  include(cmake/conan.cmake)
endif()

set_property(
  DIRECTORY
  APPEND
  PROPERTY CMAKE_CONFIGURE_DEPENDS conanfile.py
)

get_filename_component(SILKWORM_MAIN_DIR . ABSOLUTE)
set(SILKWORM_MAIN_SRC_DIR "${SILKWORM_MAIN_DIR}/silkworm")

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/compiler_settings.cmake)

if(NOT SILKWORM_CORE_ONLY)
  # Silence CMake policy warnings in submodules
  set(CMAKE_POLICY_DEFAULT_CMP0048 NEW) # project() command manages VERSION variables
  set(CMAKE_POLICY_DEFAULT_CMP0063 NEW) # Honor visibility properties for all target types

  find_package(Boost REQUIRED headers)
  # Define Boost::headers target if missing because libtorrent needs it
  if(NOT TARGET Boost::headers)
    add_library(Boost::headers INTERFACE IMPORTED)
    target_include_directories(Boost::headers INTERFACE ${Boost_INCLUDE_DIRS})
  endif()
endif()

add_subdirectory(third_party)

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/compiler_warnings.cmake)

if(SILKWORM_CLANG_TIDY)
  find_program(CLANG_TIDY clang-tidy REQUIRED)
  set(CMAKE_CXX_CLANG_TIDY "${CLANG_TIDY}")
endif()

# Silkworm itself
add_subdirectory(silkworm)

if(NOT SILKWORM_HAS_PARENT)
  add_subdirectory(cmd)
  add_subdirectory(examples)
endif()

# All unit tests target
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/common/get_all_targets.cmake)
get_all_targets(UNIT_TEST_TARGETS)
list(FILTER UNIT_TEST_TARGETS INCLUDE REGEX "_test$")
list(REMOVE_ITEM UNIT_TEST_TARGETS backend_kv_test benchmark_test sentry_client_test)
if(CMAKE_HOST_SYSTEM_NAME STREQUAL "Windows")
  # avoid fatal error C1002: compiler is out of heap space
  list(REMOVE_ITEM UNIT_TEST_TARGETS rpcdaemon_test)
endif()
message(STATUS "UNIT_TEST_TARGETS: ${UNIT_TEST_TARGETS}")
add_custom_target(all_unit_tests DEPENDS ${UNIT_TEST_TARGETS})
