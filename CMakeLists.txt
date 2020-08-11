#[[
   Copyright 2020 The Silkworm Authors

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

if(NOT EXISTS ${CMAKE_SOURCE_DIR}/evmone/evmc/.git)
  message(FATAL_ERROR "Git submodules not initialized, execute:\n  git submodule update --init --recursive")
endif()

include(evmone/cmake/cable/bootstrap.cmake)
include(CableBuildType)
include(CableToolchains)

cable_configure_toolchain(DEFAULT cxx17)
cable_set_build_type(DEFAULT Release CONFIGURATION_TYPES Release Debug)

include(evmone/cmake/cable/HunterGate.cmake)
set(HUNTER_USE_CACHE_SERVERS NO)
HunterGate(
  URL "https://github.com/cpp-pm/hunter/archive/v0.23.250.tar.gz"
  SHA1 "0e6ce3072a280110f33162e0265fb3796652673f"
  FILEPATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Hunter/config.cmake"
)

project(silkworm)

# Abseil
add_subdirectory(abseil-cpp)

# secp256k1
add_compile_definitions(USE_NUM_NONE USE_FIELD_INV_BUILTIN USE_SCALAR_INV_BUILTIN)
if(MSVC)
  add_compile_definitions(USE_FIELD_10X26 USE_SCALAR_8X32)
else()
  add_compile_definitions(USE_FIELD_5X52 USE_SCALAR_4X64 HAVE___INT128)
endif()
add_compile_definitions(ECMULT_WINDOW_SIZE=15 ECMULT_GEN_PREC_BITS=4 USE_ENDOMORPHISM)
add_compile_definitions(ENABLE_MODULE_RECOVERY)
add_library(secp256k1 secp256k1/src/secp256k1.c)
target_include_directories(secp256k1 PRIVATE secp256k1 INTERFACE secp256k1/include)

# libff
include(FindOpenSSL)
if(NOT OPENSSL_FOUND)
  hunter_add_package(OpenSSL)
endif()
option(
  WITH_PROCPS
  "Use procps for memory profiling"
  OFF
)
option(
  IS_LIBFF_PARENT
  "Install submodule dependencies if caller originates from here"
  OFF
)
add_subdirectory(libff)

# Compiler options
if(MSVC)
  add_compile_options(/W4)
  add_compile_options(/wd5030) # Silence warnings about gnu attributes
  add_compile_options(/wd4324) # Silence warning C4324: 'xxx': structure was padded due to alignment specifier
  add_compile_options(/wd4068) # Silence warning C4068: unknown pragma
else()
  add_compile_options(-Wall -Wextra -Werror -Wno-missing-field-initializers)
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES ".*Clang$")
  add_compile_options(-gline-tables-only) # for profiling
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  add_compile_options(-Wno-attributes)
endif()

# Some other required packages
hunter_add_package(ethash)
find_package(ethash CONFIG REQUIRED)
hunter_add_package(intx)
find_package(intx CONFIG REQUIRED)

add_subdirectory(evmone/evmc)

# evmone
add_library(evmone evmone/lib/evmone/analysis.cpp
                   evmone/lib/evmone/analysis.hpp
                   evmone/lib/evmone/execution_state.hpp
                   evmone/lib/evmone/instructions.cpp
                   evmone/lib/evmone/instructions.hpp
                   evmone/lib/evmone/limits.hpp
                   evmone/lib/evmone/opcodes_helpers.h)
target_include_directories(evmone PUBLIC evmone/lib/evmone)
target_link_libraries(evmone PUBLIC evmc intx::intx PRIVATE ethash::keccak)

# silkworm itself
add_subdirectory(silkworm)

add_executable(check_changes cmd/check_changes.cpp)
target_link_libraries(check_changes PRIVATE silkworm absl::flags_parse absl::time)

# Unit tests
enable_testing()

hunter_add_package(Catch)
find_package(Catch2 CONFIG REQUIRED)

file(GLOB_RECURSE SILKWORM_TESTS CONFIGURE_DEPENDS "silkworm/*_test.cpp")
add_executable(tests cmd/tests.cpp ${SILKWORM_TESTS})
target_link_libraries(tests silkworm Catch2::Catch2)

include(CTest)
include(Catch)
catch_discover_tests(tests)
