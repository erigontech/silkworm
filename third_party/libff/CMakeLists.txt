# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

set(CURVE
    "ALT_BN128"
    CACHE STRING "" FORCE
)
option(WITH_PROCPS "" OFF)
option(IS_LIBFF_PARENT "" OFF)

# reduce the log verbosity of libff/CMakeLists.txt
if(NOT CMAKE_MESSAGE_LOG_LEVEL)
  set(CMAKE_MESSAGE_LOG_LEVEL_EMPTY YES)
  set(CMAKE_MESSAGE_LOG_LEVEL NOTICE)
endif()

add_subdirectory(libff)

# restore the log verbosity
if(CMAKE_MESSAGE_LOG_LEVEL_EMPTY)
  unset(CMAKE_MESSAGE_LOG_LEVEL)
endif()
