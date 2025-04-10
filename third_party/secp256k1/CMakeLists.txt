# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

set(SECP256K1_ENABLE_MODULE_RECOVERY
    ON
    CACHE BOOL "Enable ECDSA pubkey recovery module." FORCE
)
set(BUILD_SHARED_LIBS
    OFF
    CACHE BOOL "Build shared libraries." FORCE
)
add_subdirectory(secp256k1)
