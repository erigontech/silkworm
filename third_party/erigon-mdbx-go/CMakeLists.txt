# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

set(MDBX_ENABLE_TESTS OFF)

# reduce the log verbosity of mdbx-go/mdbxdist/CMakeLists.txt
if(NOT CMAKE_MESSAGE_LOG_LEVEL)
  set(CMAKE_MESSAGE_LOG_LEVEL_EMPTY YES)
  set(CMAKE_MESSAGE_LOG_LEVEL NOTICE)
endif()

add_subdirectory(mdbx-go/libmdbx)

# restore the log verbosity
if(CMAKE_MESSAGE_LOG_LEVEL_EMPTY)
  unset(CMAKE_MESSAGE_LOG_LEVEL)
endif()

target_compile_definitions(mdbx-static PUBLIC CONSTEXPR_ASSERT=assert)

# mdbx is not compatible with TSAN and added to the suppressions config file let's suppress the related compilation
# warnings
if(SILKWORM_SANITIZE STREQUAL "thread" AND CMAKE_CXX_COMPILER_ID MATCHES "GNU")
  target_compile_options(mdbx-static PRIVATE -Wno-tsan)
endif()

if(MDBX_BUILD_TOOLS)
  foreach(
    TOOL
    mdbx_chk
    mdbx_copy
    mdbx_stat
    mdbx_dump
    mdbx_load
    mdbx_drop
  )

    if((CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang") AND (CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 15))
      # https://stackoverflow.com/questions/77164140/
      target_link_options(${TOOL} PRIVATE -Wl,-no_warn_duplicate_libraries)
    endif()
  endforeach()
endif()
