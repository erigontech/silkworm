# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

add_library(stbrumme_crc32 "stbrumme-crc32/Crc32.cpp")
target_include_directories(stbrumme_crc32 PUBLIC "stbrumme-crc32")
