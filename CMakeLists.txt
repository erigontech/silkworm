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

if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/evmone/evmc/.git)
  message(FATAL_ERROR "Git submodules not initialized, execute:\n  git submodule update --init --recursive")
endif()

get_directory_property(SILKWORM_HAS_PARENT PARENT_DIRECTORY)
if(NOT SILKWORM_HAS_PARENT)
  include(evmone/cmake/cable/bootstrap.cmake)
  include(CableBuildType)
  cable_set_build_type(DEFAULT Release CONFIGURATION_TYPES Release Debug)

  set(CMAKE_TOOLCHAIN_FILE ${CMAKE_CURRENT_SOURCE_DIR}/cmake/toolchain.cmake CACHE FILEPATH "" FORCE)

  include(evmone/cmake/cable/HunterGate.cmake)
  HunterGate(
    URL "https://github.com/cpp-pm/hunter/archive/v0.23.267.tar.gz"
    SHA1 "9c5c7fa6e17c2ae15dd922184bc7c51235aaae70"
  )
endif()

#[[
If you want to include Silkworm into your CMake project,
add the following lines before the project command of your root CMakeLists.txt:

-----------------------------------------------------------------------------------------------------
set(CMAKE_TOOLCHAIN_FILE ${CMAKE_SOURCE_DIR}/silkworm/cmake/toolchain.cmake CACHE FILEPATH "" FORCE)

include(silkworm/evmone/cmake/cable/HunterGate.cmake)
HunterGate(
  URL "https://github.com/cpp-pm/hunter/archive/v0.23.267.tar.gz"
  SHA1 "9c5c7fa6e17c2ae15dd922184bc7c51235aaae70"
)
-----------------------------------------------------------------------------------------------------

(You can update the Hunter version.)
]]

project(silkworm)

include(cmake/Hunter/packages.cmake)

# Profing and coverage options
if(CMAKE_CXX_COMPILER_ID MATCHES ".*Clang$")
  if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    # coverage
    add_compile_options(-fprofile-instr-generate -fcoverage-mapping)
    add_link_options(-fprofile-instr-generate -fcoverage-mapping)
  else()
    # profiling
    add_compile_options(-gline-tables-only)
  endif()
endif()

# secp256k1
if(MSVC)
  find_path(GMP_INCLUDE_DIR NAMES gmp.h)
  if(GMP_INCLUDE_DIR)
    message(STATUS "secp256k1 using GMP")
    add_compile_definitions(USE_NUM_GMP USE_FIELD_INV_NUM USE_SCALAR_INV_NUM)
  else()
    add_compile_definitions(USE_NUM_NONE USE_FIELD_INV_BUILTIN USE_SCALAR_INV_BUILTIN)
  endif()
  add_compile_definitions(USE_FIELD_10X26 USE_SCALAR_8X32)
else()
  add_compile_definitions(USE_NUM_NONE USE_FIELD_INV_BUILTIN USE_SCALAR_INV_BUILTIN)
  add_compile_definitions(USE_FIELD_5X52 USE_SCALAR_4X64 HAVE___INT128)
endif()
add_compile_definitions(ECMULT_WINDOW_SIZE=15 ECMULT_GEN_PREC_BITS=4 USE_ENDOMORPHISM)
add_compile_definitions(ENABLE_MODULE_RECOVERY)
add_library(secp256k1 secp256k1/src/secp256k1.c)
target_include_directories(secp256k1 PRIVATE secp256k1 INTERFACE secp256k1/include)
if(GMP_INCLUDE_DIR)
  target_include_directories(secp256k1 PRIVATE ${GMP_INCLUDE_DIR})
endif()

# libff
set(CURVE "ALT_BN128" CACHE STRING "" FORCE)
option(WITH_PROCPS "" OFF)
option(IS_LIBFF_PARENT "" OFF)
if(MSVC)
  option(MPIR_INSTEAD_OF_GMP "" ON)
endif()
add_subdirectory(libff)

# CBOR
add_subdirectory(cbor-cpp)

# LMDB
add_library(lmdb lmdb-go/lmdb/lmdb.h
                 lmdb-go/lmdb/mdb.c
                 lmdb-go/lmdb/midl.c
                 lmdb-go/lmdb/midl.h)
target_include_directories(lmdb PUBLIC lmdb-go)

# Warnings options
if(MSVC)

  add_definitions(-D_WIN32_WINNT=0x0602) # Min Windows 8
  add_definitions(-DVC_EXTRALEAN)        # Process windows headers faster ...
  add_definitions(-DWIN32_LEAN_AND_MEAN) # ... and prevent winsock mismatch with Boost's
  add_definitions(-DNOMINMAX)            # Prevent MSVC to tamper with std::min/std::max

  add_compile_definitions(_SILENCE_CXX17_OLD_ALLOCATOR_MEMBERS_DEPRECATION_WARNING)

  add_compile_options(/wd5030) # Silence warnings about GNU attributes
  add_compile_options(/wd4324) # Silence warning C4324: 'xxx': structure was padded due to alignment specifier
  add_compile_options(/wd4068) # Silence warning C4068: unknown pragma
  add_compile_options(/W4)

  add_link_options(/ignore:4099)
else()
  add_compile_options(-Wall -Wextra -Werror -Wno-missing-field-initializers)
endif()

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  add_compile_options(-Wno-attributes)
endif()

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  add_compile_definitions(_LIBCPP_ENABLE_THREAD_SAFETY_ANNOTATIONS)
  add_compile_options(-Wthread-safety)
endif()

# evmone with dependencies
add_subdirectory(evmone/evmc)
add_subdirectory(ethash)
find_package(intx CONFIG REQUIRED)

add_library(evmone evmone/lib/evmone/analysis.cpp
                   evmone/lib/evmone/analysis.hpp
                   evmone/lib/evmone/execution_state.hpp
                   evmone/lib/evmone/instructions_calls.cpp
                   evmone/lib/evmone/instructions.cpp
                   evmone/lib/evmone/instructions.hpp
                   evmone/lib/evmone/limits.hpp
                   evmone/lib/evmone/opcodes_helpers.h)

target_include_directories(evmone PUBLIC evmone/lib/evmone)
target_link_libraries(evmone PUBLIC evmc intx::intx PRIVATE keccak)

# Silkworm itself
add_subdirectory(core)
add_subdirectory(db)
add_subdirectory(tg_api)
if(NOT SILKWORM_HAS_PARENT)
  add_subdirectory(cmd)
endif()
