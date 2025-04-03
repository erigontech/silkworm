# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

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
