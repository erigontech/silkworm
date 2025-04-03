# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

add_library(stbrumme_keccak "stbrumme-keccak/keccak.cpp")
target_include_directories(stbrumme_keccak PUBLIC "stbrumme-keccak")
