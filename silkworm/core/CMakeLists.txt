# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

include("${SILKWORM_MAIN_DIR}/cmake/common/targets.cmake")

find_package(Catch2 REQUIRED)
find_package(magic_enum REQUIRED)
find_package(Microsoft.GSL REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(tl-expected REQUIRED)

if(SILKWORM_CORE_ONLY)
  if(MSVC)
    add_compile_options(/EHsc)
  else()
    add_compile_options(-fno-exceptions)
  endif()
endif()

set(SILKWORM_CORE_PUBLIC_LIBS
    ethash::ethash
    evmc
    evmone
    intx::intx
    magic_enum::magic_enum
    Microsoft.GSL::GSL
    nlohmann_json::nlohmann_json
    secp256k1
    tl::expected
)
set(SILKWORM_CORE_PRIVATE_LIBS ff blst::blst)

if(SILKWORM_CORE_USE_ABSEIL)
  find_package(absl REQUIRED)
  list(APPEND SILKWORM_CORE_PUBLIC_LIBS absl::flat_hash_map absl::flat_hash_set)
endif()

silkworm_library(
  silkworm_core
  PUBLIC ${SILKWORM_CORE_PUBLIC_LIBS}
  PRIVATE ${SILKWORM_CORE_PRIVATE_LIBS}
)

if(SILKWORM_CORE_USE_ABSEIL)
  target_compile_definitions(silkworm_core PUBLIC SILKWORM_CORE_USE_ABSEIL)
endif()

# unit tests
set(TEST_TARGET silkworm_core_test)

if(SILKWORM_WASM_API)
  # Stub clang exception handlers on WASM after Catch2 3.x due to https://github.com/WebAssembly/wasi-sdk/issues/329
  target_sources(${TEST_TARGET} PRIVATE "${SILKWORM_MAIN_SRC_DIR}/wasm/exception_handling_stub.cpp")
  # Skip generation of RPATH linker option for wasm-ld present by default after building Catch2 v3.6.0 from sources
  set_target_properties(${TEST_TARGET} PROPERTIES SKIP_BUILD_RPATH TRUE)
endif()

if(SILKWORM_CORE_ONLY)
  if(MSVC)
    target_compile_options(${TEST_TARGET} PRIVATE /EHa- /EHsc)
  else()
    target_compile_options(${TEST_TARGET} PRIVATE -fno-exceptions)
  endif()
endif()
