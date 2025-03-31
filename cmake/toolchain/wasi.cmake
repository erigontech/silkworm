# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

set(CMAKE_C_COMPILER /opt/wasi-sdk/bin/clang)
set(CMAKE_CXX_COMPILER /opt/wasi-sdk/bin/clang++)

add_compile_definitions(CATCH_CONFIG_NO_POSIX_SIGNALS JSON_HAS_FILESYSTEM=0)

include(${CMAKE_CURRENT_LIST_DIR}/cxx20.cmake)
