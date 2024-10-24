#[[
   Copyright 2022 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
]]

find_package(Catch2 REQUIRED)
find_package(magic_enum REQUIRED)

# Silkworm Core Tests
file(GLOB_RECURSE SILKWORM_CORE_TESTS CONFIGURE_DEPENDS "${SILKWORM_MAIN_SRC_DIR}/core/*_test.cpp")
if(SILKWORM_WASM_API)
  # Stub clang exception handlers on WASM after Catch2 3.x due to https://github.com/WebAssembly/wasi-sdk/issues/329
  add_executable(core_test "${SILKWORM_MAIN_SRC_DIR}/wasm/exception_handling_stub.cpp" ${SILKWORM_CORE_TESTS})
  # Skip generation of RPATH linker option for wasm-ld present by default after building Catch2 v3.6.0 from sources
  set_target_properties(core_test PROPERTIES SKIP_BUILD_RPATH TRUE)
else()
  add_executable(core_test ${SILKWORM_CORE_TESTS})
endif()
target_link_libraries(core_test silkworm_core Catch2::Catch2WithMain)

if(SILKWORM_CORE_ONLY)
  if(MSVC)
    target_compile_options(core_test PRIVATE /EHa- /EHsc)
  else()
    target_compile_options(core_test PRIVATE -fno-exceptions)
  endif()
endif()

if(NOT SILKWORM_CORE_ONLY)

  # Enable fuzzing tests for Clang builds only
  if("${CMAKE_CXX_COMPILER_ID}" MATCHES ".*Clang$" AND SILKWORM_FUZZER)
    # Silkworm RpcDaemon Fuzzer Tests
    add_executable(rpcdaemon_fuzzer_test fuzzer_test.cpp)
    target_compile_options(rpcdaemon_fuzzer_test PRIVATE -fsanitize=fuzzer)
    target_link_libraries(
      rpcdaemon_fuzzer_test PRIVATE silkworm_rpcdaemon silkworm_infra_test_util silkworm_rpcdaemon_test_util
    )
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
  endif()

  # Ethereum EL Tests (https://github.com/ethereum/tests)
  find_package(CLI11 REQUIRED)
  add_executable(ethereum ethereum.cpp)
  target_compile_definitions(
    ethereum PRIVATE SILKWORM_ETHEREUM_TESTS_DIR= "${SILKWORM_MAIN_DIR}/third_party/ethereum-tests"
  )
  target_link_libraries(ethereum PRIVATE silkworm_infra evmc::loader CLI11::CLI11 magic_enum::magic_enum)

  # BE&KV Tests
  add_executable(backend_kv_test "backend_kv_test.cpp" "../common/shutdown_signal.hpp" "../common/shutdown_signal.cpp")
  target_link_libraries(backend_kv_test PRIVATE silkworm_node CLI11::CLI11 magic_enum::magic_enum)

  add_executable(sentry_client_test "sentry_client_test.cpp")
  target_link_libraries(sentry_client_test PRIVATE silkworm_sentry)
endif()
