# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

include(${CMAKE_CURRENT_LIST_DIR}/cxx20.cmake)

# coroutines support
set(CMAKE_CXX_FLAGS
    "${CMAKE_CXX_FLAGS} -stdlib=libc++"
    CACHE STRING "" FORCE
)
