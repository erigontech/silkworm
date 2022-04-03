#[[
   Copyright 2020-2022 The Silkworm Authors

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

# ethash requires cmake 3.16.2
cmake_minimum_required(VERSION 3.16.2)

if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/third_party/evmone/evmc/.git)
  message(FATAL_ERROR "Git submodules not initialized, execute:\n  git submodule update --init --recursive")
endif()

get_directory_property(SILKWORM_HAS_PARENT PARENT_DIRECTORY)
if(NOT SILKWORM_HAS_PARENT)
  include(third_party/evmone/cmake/cable/bootstrap.cmake)
  include(CableBuildType)
  include(CableBuildInfo)
  cable_set_build_type(DEFAULT Release CONFIGURATION_TYPES Release Debug)

  if(NOT CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE ${CMAKE_CURRENT_SOURCE_DIR}/cmake/toolchain/cxx17.cmake CACHE FILEPATH "" FORCE)
  endif()

  include(third_party/evmone/cmake/cable/HunterGate.cmake)
  HunterGate(
    URL "https://github.com/cpp-pm/hunter/archive/v0.23.317.tar.gz"
    SHA1 "fbdd94b1966d351384e27b02c8d134915b1131d6"
    LOCAL
    )
endif()

#[[
If you want to include Silkworm into your CMake project,
add the following lines before the project command of your root CMakeLists.txt:

-----------------------------------------------------------------------------------------------------
include(silkworm/third_party/evmone/cmake/cable/bootstrap.cmake)
include(CableBuildInfo)
include(silkworm/third_party/evmone/cmake/cable/HunterGate.cmake)
HunterGate(
  URL "https://github.com/cpp-pm/hunter/archive/v0.23.317.tar.gz"
  SHA1 "fbdd94b1966d351384e27b02c8d134915b1131d6"
  FILEPATH "${CMAKE_SOURCE_DIR}/silkworm/cmake/Hunter/config.cmake"
)

-----------------------------------------------------------------------------------------------------

(You can update the Hunter version, but keep the FILEPATH option.)
]]

project(silkworm)

cable_add_buildinfo_library(PROJECT_NAME ${PROJECT_NAME})

option(SILKWORM_WASM_API "Build WebAssembly API" OFF)
option(SILKWORM_CORE_ONLY "Only build Silkworm Core" OFF)
option(SILKWORM_CLANG_COVERAGE "Clang instrumentation for code coverage reports" OFF)
option(SILKWORM_SANITIZE "Build instrumentation for sanitizers" OFF)

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/compiler_settings.cmake)

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/Hunter/core_packages.cmake)
if(NOT SILKWORM_CORE_ONLY)
  include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/Hunter/extra_packages.cmake)
endif()


# GMP
find_path(GMP_INCLUDE_DIR NAMES gmp.h)
if(MSVC)
  find_library(GMP_LIBRARY mpir)
else()
  find_library(GMP_LIBRARY gmp)
endif()
if(GMP_LIBRARY MATCHES ${CMAKE_SHARED_LIBRARY_SUFFIX})
  set(gmp_library_type SHARED)
else()
  set(gmp_library_type STATIC)
endif()
message(STATUS "GMP: ${GMP_LIBRARY}, ${GMP_INCLUDE_DIR}")
add_library(gmp ${gmp_library_type} IMPORTED)
set_target_properties(
  gmp PROPERTIES
  IMPORTED_LOCATION ${GMP_LIBRARY}
  INTERFACE_INCLUDE_DIRECTORIES ${GMP_INCLUDE_DIR}
)

if(NOT SILKWORM_CORE_ONLY)

  # Roaring Bitmaps
  option(ENABLE_ROARING_TESTS "" OFF)
  option(ROARING_BUILD_STATIC "Build a static library" ON)
  if(NOT MSVC)
    # Not supported on MSVC
    option(ROARING_LINK_STATIC "Link executables (tests, benchmarks) statically" ON)
  endif()
  add_subdirectory(third_party/CRoaring EXCLUDE_FROM_ALL)

  # CBOR
  add_subdirectory(third_party/cbor-cpp)
    
endif()

# evmone with dependencies
if(SILKWORM_WASM_API)
  add_compile_definitions(EVMC_LOADER_MOCK)
endif()

find_package(intx CONFIG REQUIRED)   # Required from here below
find_package(ethash CONFIG REQUIRED) # Required from here below

add_subdirectory(third_party/evmone/evmc)

add_library(evmone third_party/evmone/lib/evmone/advanced_analysis.cpp
                   third_party/evmone/lib/evmone/advanced_analysis.hpp
                   third_party/evmone/lib/evmone/advanced_execution.cpp
                   third_party/evmone/lib/evmone/advanced_execution.hpp
                   third_party/evmone/lib/evmone/advanced_instructions.cpp
                   third_party/evmone/lib/evmone/baseline_instruction_table.cpp
                   third_party/evmone/lib/evmone/baseline_instruction_table.hpp
                   third_party/evmone/lib/evmone/baseline.cpp
                   third_party/evmone/lib/evmone/baseline.hpp
                   third_party/evmone/lib/evmone/execution_state.hpp
                   third_party/evmone/lib/evmone/instructions_calls.cpp
                   third_party/evmone/lib/evmone/instructions_traits.hpp
                   third_party/evmone/lib/evmone/instructions_xmacro.hpp
                   third_party/evmone/lib/evmone/instructions.hpp
                   third_party/evmone/lib/evmone/opcodes_helpers.h
                   third_party/evmone/lib/evmone/tracing.cpp
                   third_party/evmone/lib/evmone/tracing.hpp
                   third_party/evmone/lib/evmone/vm.cpp
                   third_party/evmone/lib/evmone/vm.hpp)
set_source_files_properties(third_party/evmone/lib/evmone/vm.cpp PROPERTIES COMPILE_DEFINITIONS PROJECT_VERSION="0.9.0-dev")
target_include_directories(evmone PUBLIC third_party/evmone/include third_party/evmone/lib)
target_link_libraries(evmone PUBLIC evmc intx::intx PRIVATE evmc::instructions evmc::hex)

if(MSVC)
  target_compile_options(evmone PRIVATE /EHsc /w)
else()
  target_compile_options(evmone PRIVATE -fno-exceptions)
endif()

# MDBX
if(NOT SILKWORM_CORE_ONLY)
  set(MDBX_ENABLE_TESTS OFF)
  add_subdirectory(third_party/libmdbx)
  target_include_directories(mdbx-static INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/third_party/libmdbx)
endif()

add_subdirectory(third_party/silkpre)

# Compiler enforcements on Silkworm
if(NOT MSVC)
  add_compile_options(-Werror -Wall -Wextra)
  add_compile_options(-Wshadow -Wimplicit-fallthrough -Wsign-conversion)
  add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-Wold-style-cast>)
  add_compile_options(-Wno-missing-field-initializers)
  if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    add_compile_options(-Wno-attributes)
  endif()
  if(CMAKE_CXX_COMPILER_ID MATCHES "Clang" AND CMAKE_SYSTEM_NAME MATCHES "Darwin")
    add_compile_definitions(_LIBCPP_ENABLE_THREAD_SAFETY_ANNOTATIONS)
    add_compile_options(-Wthread-safety)
  endif()
endif()

# Silkworm itself
add_subdirectory(core)

if(NOT SILKWORM_CORE_ONLY)
  add_subdirectory(interfaces)
  add_subdirectory(node)
endif()

if(NOT SILKWORM_HAS_PARENT)
  add_subdirectory(cmd)
endif()

if(SILKWORM_WASM_API)
  add_subdirectory(wasm)
endif()
