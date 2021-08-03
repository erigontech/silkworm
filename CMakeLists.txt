#[[
   Copyright 2020-2021 The Silkworm Authors

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

cmake_minimum_required(VERSION 3.13)

if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/evmone/evmc/.git)
  message(FATAL_ERROR "Git submodules not initialized, execute:\n  git submodule update --init --recursive")
endif()

get_directory_property(SILKWORM_HAS_PARENT PARENT_DIRECTORY)
if(NOT SILKWORM_HAS_PARENT)
  include(evmone/cmake/cable/bootstrap.cmake)
  include(CableBuildType)
  cable_set_build_type(DEFAULT Release CONFIGURATION_TYPES Release Debug)

  if(NOT CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE ${CMAKE_CURRENT_SOURCE_DIR}/cmake/toolchain.cmake CACHE FILEPATH "" FORCE)
  endif()

  include(evmone/cmake/cable/HunterGate.cmake)
  HunterGate(
    URL "https://github.com/cpp-pm/hunter/archive/v0.23.288.tar.gz"
    SHA1 "6c9b2bc606d86ae31f96a62fc68f0a593024815b"
    LOCAL
    )
endif()

#[[
If you want to include Silkworm into your CMake project,
add the following lines before the project command of your root CMakeLists.txt:

-----------------------------------------------------------------------------------------------------
set(CMAKE_TOOLCHAIN_FILE ${CMAKE_SOURCE_DIR}/silkworm/cmake/toolchain.cmake CACHE FILEPATH "" FORCE)

include(silkworm/evmone/cmake/cable/HunterGate.cmake)
HunterGate(
  URL "https://github.com/cpp-pm/hunter/archive/v0.23.288.tar.gz"
  SHA1 "6c9b2bc606d86ae31f96a62fc68f0a593024815b"
  FILEPATH "${CMAKE_SOURCE_DIR}/silkworm/cmake/Hunter/config.cmake"
)
-----------------------------------------------------------------------------------------------------

(You can update the Hunter version, but keep the FILEPATH option.)
]]

project(silkworm)

option(SILKWORM_WASM_API "Build WebAssembly API" OFF)
option(SILKWORM_CORE_ONLY "Only build Silkworm Core" OFF)
option(SILKWORM_CLANG_COVERAGE "Clang instrumentation for code coverage reports" OFF)

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

# secp256k1
add_library(secp256k1 secp256k1/src/secp256k1.c)

if(MSVC)

  target_link_libraries(secp256k1 PRIVATE gmp)
  target_compile_definitions(secp256k1 PUBLIC USE_NUM_GMP USE_FIELD_INV_NUM USE_SCALAR_INV_NUM)
  target_compile_definitions(secp256k1 PUBLIC USE_FIELD_10X26 USE_SCALAR_8X32)

  target_compile_options(secp256k1 PRIVATE /w) # Not much we can do about warnings

else()

  target_compile_definitions(secp256k1 PUBLIC USE_NUM_NONE USE_FIELD_INV_BUILTIN USE_SCALAR_INV_BUILTIN)
  target_compile_definitions(secp256k1 PUBLIC USE_FIELD_5X52 USE_SCALAR_4X64 HAVE___INT128)

endif()

target_compile_definitions(secp256k1 PUBLIC ECMULT_WINDOW_SIZE=15 ECMULT_GEN_PREC_BITS=4 USE_ENDOMORPHISM)
target_compile_definitions(secp256k1 PUBLIC ENABLE_MODULE_RECOVERY)
target_include_directories(secp256k1 PRIVATE secp256k1 INTERFACE secp256k1/include)

# libff
set(CURVE "ALT_BN128" CACHE STRING "" FORCE)
option(WITH_PROCPS "" OFF)
option(IS_LIBFF_PARENT "" OFF)
if(MSVC)
  option(MPIR_INSTEAD_OF_GMP "" ON)
endif()
add_subdirectory(libff)

if(NOT SILKWORM_CORE_ONLY)

  # Roaring Bitmaps
  set(ENABLE_ROARING_TESTS OFF)
  option(ROARING_BUILD_STATIC "Build a static library" ON)
  if(NOT MSVC)
    # Not supported on MSVC
    option(ROARING_LINK_STATIC "Link executables (tests, benchmarks) statically" ON)
  endif()
  add_subdirectory(CRoaring EXCLUDE_FROM_ALL)

  # CBOR
  add_subdirectory(cbor-cpp)
    
endif()

# evmone with dependencies
if(SILKWORM_WASM_API)
  add_compile_definitions(EVMC_LOADER_MOCK)
endif()

find_package(intx CONFIG REQUIRED)   # Required from here below
find_package(ethash CONFIG REQUIRED) # Required from here below

add_subdirectory(evmone/evmc)

add_library(evmone evmone/lib/evmone/analysis.cpp
                   evmone/lib/evmone/analysis.hpp
                   evmone/lib/evmone/baseline_instruction_table.cpp
                   evmone/lib/evmone/baseline_instruction_table.hpp
                   evmone/lib/evmone/baseline.cpp
                   evmone/lib/evmone/baseline.hpp
                   evmone/lib/evmone/execution_state.hpp
                   evmone/lib/evmone/execution.cpp
                   evmone/lib/evmone/execution.hpp
                   evmone/lib/evmone/instruction_traits.hpp
                   evmone/lib/evmone/instructions_calls.cpp
                   evmone/lib/evmone/instructions.cpp
                   evmone/lib/evmone/instructions.hpp
                   evmone/lib/evmone/limits.hpp
                   evmone/lib/evmone/opcodes_helpers.h
                   evmone/lib/evmone/tracing.cpp
                   evmone/lib/evmone/tracing.hpp
                   evmone/lib/evmone/vm.cpp
                   evmone/lib/evmone/vm.hpp)
set_source_files_properties(evmone/lib/evmone/vm.cpp PROPERTIES COMPILE_DEFINITIONS PROJECT_VERSION="0.8.1")
target_include_directories(evmone PUBLIC evmone/include evmone/lib)
target_link_libraries(evmone PUBLIC evmc intx::intx PRIVATE evmc::instructions evmc::hex)

if(MSVC)
  target_compile_options(evmone PRIVATE /EHsc /w)
else()
  target_compile_options(evmone PRIVATE -fno-exceptions)
endif()


# Compiler enforcements on Silkworm
if(NOT MSVC)
  add_compile_options(-Wall -Wextra -Werror -Wno-missing-field-initializers)
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
  set(MDBX_ENABLE_TESTS OFF)
  add_subdirectory(libmdbx)
  target_include_directories(mdbx-static INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/libmdbx)
  add_subdirectory(db)
endif()

if(NOT SILKWORM_HAS_PARENT)
  add_subdirectory(cmd)
endif()

if(SILKWORM_WASM_API)
  add_subdirectory(wasm)
endif()
