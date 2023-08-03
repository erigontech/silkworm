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

include(ExternalProject)

# GMP
#
# declaring it first to be used by intx, libff
if(DEFINED GMP_LIBRARY)
  add_library(gmplib STATIC IMPORTED)
  set_target_properties(gmplib PROPERTIES IMPORTED_LOCATION "${GMP_LIBRARY}")
  if(DEFINED GMP_INCLUDE_DIR)
    set_target_properties(gmplib PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${GMP_INCLUDE_DIR}")
  else()
    message(FATAL_ERROR "GMP_INCLUDE_DIR is required if a custom GMP_LIBRARY is provided")
  endif()
else()
  find_package(gmp REQUIRED)
  add_custom_target(gmplib DEPENDS gmp::GMP)

  # derive the path variables from the package for intx, libff
  get_target_property(GMP_INCLUDE_DIR gmp::GMP INTERFACE_INCLUDE_DIRECTORIES)
  set(GMP_INCLUDE_DIR
      "${GMP_INCLUDE_DIR}"
      CACHE PATH ""
  )
  get_target_property(GMP_LIBRARY_DIR gmp::GMP INTERFACE_LINK_DIRECTORIES)
  find_library(GMP_LIBRARY gmp "${GMP_LIBRARY_DIR}")
endif()

# evmone with dependencies
find_package(intx REQUIRED)

option(ETHASH_BUILD_GLOBAL_CONTEXT "" OFF)
add_subdirectory(ethash)

if(SILKWORM_WASM_API)
  add_compile_definitions(EVMC_LOADER_MOCK)
endif()
add_subdirectory(evmone/evmc)

add_library(
  evmone
  evmone/lib/evmone/advanced_analysis.cpp
  evmone/lib/evmone/advanced_analysis.hpp
  evmone/lib/evmone/advanced_execution.cpp
  evmone/lib/evmone/advanced_execution.hpp
  evmone/lib/evmone/advanced_instructions.cpp
  evmone/lib/evmone/baseline_instruction_table.cpp
  evmone/lib/evmone/baseline_instruction_table.hpp
  evmone/lib/evmone/baseline.cpp
  evmone/lib/evmone/baseline.hpp
  evmone/lib/evmone/eof.cpp
  evmone/lib/evmone/eof.hpp
  evmone/lib/evmone/execution_state.hpp
  evmone/lib/evmone/instructions_calls.cpp
  evmone/lib/evmone/instructions_opcodes.hpp
  evmone/lib/evmone/instructions_storage.cpp
  evmone/lib/evmone/instructions_traits.hpp
  evmone/lib/evmone/instructions_xmacro.hpp
  evmone/lib/evmone/instructions.hpp
  evmone/lib/evmone/opcodes_helpers.h
  evmone/lib/evmone/tracing.cpp
  evmone/lib/evmone/tracing.hpp
  evmone/lib/evmone/vm.cpp
  evmone/lib/evmone/vm.hpp
)
set_source_files_properties(evmone/lib/evmone/vm.cpp PROPERTIES COMPILE_DEFINITIONS PROJECT_VERSION="0.10.0")
target_include_directories(evmone PUBLIC evmone/include evmone/lib)
target_link_libraries(
  evmone
  PUBLIC evmc intx::intx
  PRIVATE ethash::keccak
)

if(MSVC)
  target_compile_options(evmone PRIVATE /EHsc /w)
else()
  target_compile_options(evmone PRIVATE -fno-exceptions)
endif()

# secp256k1
add_library(secp256k1 secp256k1/src/secp256k1.c)
if(MSVC)
  target_compile_options(secp256k1 PRIVATE /w) # Not much we can do about warnings
endif()
# cmake-format: off
target_compile_definitions(
  secp256k1
  PUBLIC ECMULT_WINDOW_SIZE=15
         ECMULT_GEN_PREC_BITS=4
         ENABLE_MODULE_ECDH
         ENABLE_MODULE_RECOVERY
)
# cmake-format: on
target_include_directories(
  secp256k1
  PRIVATE secp256k1
  INTERFACE secp256k1/include
)

# libff
set(CURVE
    "ALT_BN128"
    CACHE STRING "" FORCE
)
option(WITH_PROCPS "" OFF)
option(IS_LIBFF_PARENT "" OFF)
add_subdirectory(libff)
if(NOT MSVC)
  add_dependencies(ff gmplib)
endif()

# BLST
set(BLST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/blst)
if(SILKWORM_WASM_API)
  set(BLST_BUILD_SCRIPT ./build.sh CC=/opt/wasi-sdk/bin/clang -D__BLST_PORTABLE__)
  set(BLST_LIB libblst.a)
elseif(MSVC)
  set(BLST_BUILD_SCRIPT build.bat)
  set(BLST_LIB blst.lib)
else()
  set(BLST_BUILD_SCRIPT ./build.sh)
  set(BLST_LIB libblst.a)
endif()

ExternalProject_Add(
  blst_build
  SOURCE_DIR ${BLST_DIR}
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ${BLST_BUILD_SCRIPT}
  BUILD_IN_SOURCE 1
  BUILD_BYPRODUCTS ${BLST_DIR}/${BLST_LIB}
  INSTALL_COMMAND ""
)

add_library(blst STATIC IMPORTED GLOBAL)
add_dependencies(blst blst_build)
# cmake-format: off
set_target_properties(
  blst
  PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${BLST_DIR}/bindings
             IMPORTED_LOCATION ${BLST_DIR}/${BLST_LIB}
)
# cmake-format: on

if(NOT SILKWORM_CORE_ONLY)
  # MDBX
  set(MDBX_ENABLE_TESTS OFF)
  add_subdirectory(libmdbx)
  target_include_directories(mdbx-static INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/libmdbx)
  target_compile_definitions(mdbx-static PUBLIC CONSTEXPR_ASSERT=assert)

  # libtorrent
  add_subdirectory(libtorrent)
  target_compile_options(torrent-rasterbar PRIVATE -w)

  add_subdirectory(cbor-cpp)
  add_subdirectory(glaze)
endif()
