if(SILKWORM_FUZZER)
  set(SILKWORM_FUZZER_LIBFUZZER_PATH
      "${CMAKE_CURRENT_SOURCE_DIR}/lib_libc++/clang/15.0.7/lib/x86_64-linux/libclang_rt.fuzzer.a"
      CACHE INTERNAL "Path to libFuzzer"
  )
  message(STATUS "Using libFuzzer from ${SILKWORM_FUZZER_LIBFUZZER_PATH}")
endif()
