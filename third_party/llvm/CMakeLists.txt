# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

if(SILKWORM_FUZZER)
  set(SILKWORM_FUZZER_LIBFUZZER_PATH
      "${CMAKE_CURRENT_SOURCE_DIR}/lib_libc++/clang/16.0.6/lib/x86_64-linux/libclang_rt.fuzzer.a"
      CACHE INTERNAL "Path to libFuzzer"
  )
  message(STATUS "Using libFuzzer from ${SILKWORM_FUZZER_LIBFUZZER_PATH}")
endif()
