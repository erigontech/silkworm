# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

# please keep the list sorted
add_subdirectory(blst)
add_subdirectory(ethash)
add_subdirectory(gmp)
add_subdirectory(intx) # depends on gmp
add_subdirectory(libff) # depends on gmp
add_subdirectory(secp256k1)

add_subdirectory(evmone) # depends on ethash, intx

# please keep the list sorted
if(NOT SILKWORM_CORE_ONLY)
  add_subdirectory(cbor-cpp)
  add_subdirectory(cpp-base64)
  add_subdirectory(erigon-mdbx-go)
  add_subdirectory(glaze)
  add_subdirectory(sais-lite)
  add_subdirectory(stbrumme-crc32)
  add_subdirectory(stbrumme-keccak)
  add_subdirectory(stun-msg)
  add_subdirectory(llvm)
endif()
