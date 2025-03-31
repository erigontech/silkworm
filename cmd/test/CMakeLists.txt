# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

find_package(magic_enum REQUIRED)

if(NOT SILKWORM_CORE_ONLY)

  # Enable fuzzing tests for Clang builds only
  if("${CMAKE_CXX_COMPILER_ID}" MATCHES ".*Clang$" AND SILKWORM_FUZZER)

    # Silkworm RpcDaemon Fuzzer Tests
    add_executable(rpcdaemon_fuzzer_test fuzzer_test.cpp)
    target_link_libraries(
      rpcdaemon_fuzzer_test PRIVATE silkworm_rpcdaemon silkworm_infra_test_util silkworm_rpcdaemon_test_util
    )

    target_compile_options(rpcdaemon_fuzzer_test PRIVATE -fsanitize=fuzzer)
    if(SILKWORM_FUZZER_LIBFUZZER_PATH)
      target_link_libraries(rpcdaemon_fuzzer_test PRIVATE ${SILKWORM_FUZZER_LIBFUZZER_PATH})
    else()
      target_link_libraries(rpcdaemon_fuzzer_test PRIVATE -fsanitize=fuzzer)
    endif()

    # Silkworm RpcDaemon Fuzzer Diagnostic
    add_executable(rpcdaemon_fuzzer_diagnostics fuzzer_diagnostics.cpp)
    target_link_libraries(
      rpcdaemon_fuzzer_diagnostics PRIVATE silkworm_rpcdaemon silkworm_infra_test_util silkworm_rpcdaemon_test_util
                                           CLI11::CLI11
    )

    if(SILKWORM_FUZZER_SANITIZERS)
      target_compile_options(rpcdaemon_fuzzer_test PRIVATE -fsanitize=${SILKWORM_FUZZER_SANITIZERS})
      target_compile_options(rpcdaemon_fuzzer_diagnostics PRIVATE -fsanitize=${SILKWORM_FUZZER_SANITIZERS})
      target_link_libraries(rpcdaemon_fuzzer_test PRIVATE -fsanitize=${SILKWORM_FUZZER_SANITIZERS})
      target_link_libraries(rpcdaemon_fuzzer_diagnostics PRIVATE -fsanitize=${SILKWORM_FUZZER_SANITIZERS})
    endif()

  endif()

  # Ethereum EL Tests (https://github.com/ethereum/tests)
  find_package(CLI11 REQUIRED)
  add_executable(ethereum ethereum.cpp)
  target_compile_definitions(
    ethereum PRIVATE SILKWORM_ETHEREUM_TESTS_DIR="${SILKWORM_MAIN_DIR}/third_party/ethereum-tests"
  )
  target_link_libraries(ethereum PRIVATE silkworm_infra evmc::loader CLI11::CLI11 magic_enum::magic_enum)

  # BE&KV Tests
  add_executable(backend_kv_test backend_kv_test.cpp)
  target_link_libraries(backend_kv_test PRIVATE silkworm_infra_cli silkworm_node CLI11::CLI11 magic_enum::magic_enum)

  add_executable(sentry_client_test sentry_client_test.cpp)
  target_link_libraries(sentry_client_test PRIVATE silkworm_sentry)
endif()
