# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

# Avoid warning about DOWNLOAD_EXTRACT_TIMESTAMP in CMake 3.24
if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.24.0")
  cmake_policy(SET CMP0135 NEW)
endif()

include(../evmone/evmone/cmake/blst.cmake)
