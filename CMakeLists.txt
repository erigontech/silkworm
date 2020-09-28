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
  URL "https://github.com/cpp-pm/hunter/archive/v0.23.267.tar.gz"
  SHA1 "9c5c7fa6e17c2ae15dd922184bc7c51235aaae70"
  FILEPATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Hunter/config.cmake"
)

project(silkworm)

if(MSVC)
  add_compile_definitions(_SILENCE_CXX17_OLD_ALLOCATOR_MEMBERS_DEPRECATION_WARNING)
endif()

hunter_add_package(abseil)
find_package(absl CONFIG REQUIRED)

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
set(
  CURVE
  "ALT_BN128"
  CACHE
  STRING
  "Default curve: one of ALT_BN128, BN128, EDWARDS, MNT4, MNT6"
  FORCE
)
option(WITH_PROCPS "" OFF)
option(IS_LIBFF_PARENT "" OFF)
if(MSVC)
  option(MPIR_INSTEAD_OF_GMP "" ON)
endif()
add_subdirectory(libff)

# Compiler options
if(MSVC)
  add_compile_options(/wd5030) # Silence warnings about GNU attributes
  add_compile_options(/wd4324) # Silence warning C4324: 'xxx': structure was padded due to alignment specifier
  add_compile_options(/wd4068) # Silence warning C4068: unknown pragma

  add_link_options(/ignore:4099)
  add_link_options(/STACK:10000000)
else()
  add_compile_options(-Wall -Wextra -Werror -Wno-missing-field-initializers)
endif()

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  add_compile_options(-Wno-attributes)
elseif(CMAKE_CXX_COMPILER_ID MATCHES ".*Clang$")
  if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    # coverage
    add_compile_options(-fprofile-instr-generate -fcoverage-mapping)
    add_link_options(-fprofile-instr-generate -fcoverage-mapping)
  else()
    # profiling
    add_compile_options(-gline-tables-only)
  endif()
endif()

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  add_link_options(-Wl,-stack_size -Wl,0x1000000)
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

# Silkworm itself
add_subdirectory(silkworm)
hunter_add_package(Boost COMPONENTS system filesystem chrono)

add_executable(check_changes cmd/check_changes.cpp)
target_link_libraries(check_changes PRIVATE silkworm absl::flags_parse absl::time Boost::filesystem)

find_package(Boost CONFIG REQUIRED COMPONENTS system filesystem chrono)
hunter_add_package(CLI11)
find_package(CLI11 CONFIG REQUIRED)

add_executable(check_senders cmd/check_senders.cpp)
target_link_libraries(check_senders PRIVATE silkworm Boost::boost Boost::filesystem Boost::chrono CLI11::CLI11)

add_executable(check_db cmd/check_db.cpp)
target_link_libraries(check_db PRIVATE silkworm Boost::boost Boost::filesystem Boost::chrono CLI11::CLI11)

# Ethereum Consensus Tests
hunter_add_package(nlohmann_json)
find_package(nlohmann_json CONFIG REQUIRED)

add_compile_definitions(SILKWORM_CONSENSUS_TEST_DIR="${CMAKE_SOURCE_DIR}/tests")

add_executable(consensus cmd/consensus.cpp)
target_link_libraries(consensus PRIVATE silkworm nlohmann_json::nlohmann_json Boost::filesystem)

# Unit tests
enable_testing()

hunter_add_package(Catch)
find_package(Catch2 CONFIG REQUIRED)

file(GLOB_RECURSE SILKWORM_TESTS CONFIGURE_DEPENDS "silkworm/*_test.cpp")
add_executable(unit_test cmd/unit_test.cpp ${SILKWORM_TESTS})
target_link_libraries(unit_test silkworm Catch2::Catch2)

include(CTest)
include(Catch)
catch_discover_tests(unit_test)
