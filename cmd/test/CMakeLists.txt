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
find_package(GTest REQUIRED)

# Silkworm Core Tests
file(GLOB_RECURSE SILKWORM_CORE_TESTS CONFIGURE_DEPENDS "${SILKWORM_MAIN_SRC_DIR}/core/*_test.cpp")
add_executable(core_test unit_test.cpp ${SILKWORM_CORE_TESTS})

target_link_libraries(core_test silkworm_core Catch2::Catch2)

if(MSVC)
  target_compile_options(core_test PRIVATE /EHa- /EHsc)
else()
  target_compile_options(core_test PRIVATE -fno-exceptions)
endif()

if(NOT SILKWORM_CORE_ONLY)
  find_package(GTest REQUIRED)

  # Silkworm Node Tests
  file(GLOB_RECURSE SILKWORM_NODE_TESTS CONFIGURE_DEPENDS "${SILKWORM_MAIN_SRC_DIR}/node/*_test.cpp")
  add_executable(node_test unit_test.cpp ${SILKWORM_NODE_TESTS})
  target_link_libraries(node_test silkworm_node Catch2::Catch2)

  # Silkworm RpcDaemon Tests
  file(GLOB_RECURSE SILKWORM_RPCDAEMON_TESTS CONFIGURE_DEPENDS "${SILKWORM_MAIN_SRC_DIR}/silkrpc/*_test.cpp")
  add_executable(rpcdaemon_test unit_test.cpp ${SILKWORM_RPCDAEMON_TESTS})
  target_link_libraries(rpcdaemon_test silkrpc Catch2::Catch2 GTest::gmock)

  # Enable fuzzing tests only for Clang sanitizer builds
  if ("${CMAKE_CXX_COMPILER_ID}" MATCHES ".*Clang$" SILKWORM_SANITIZE)
    # Silkworm RpcDaemon Fuzz Tests 
    add_executable(rpcdaemon_fuzzer_test fuzzer_test.cpp)
    target_compile_options(rpcdaemon_fuzzer_test PRIVATE -fsanitize=fuzzer,address)
    target_link_libraries(rpcdaemon_fuzzer_test PRIVATE silkrpc -fsanitize=fuzzer,address)

    # Silkworm RpcDaemon Fuzz Debug Executable
    add_executable(rpcdaemon_fuzzer_diagnosis fuzzer_diagnosis.cpp)
    target_link_libraries(rpcdaemon_fuzzer_diagnosis PRIVATE silkrpc CLI11::CLI11)
  endif()

  # Silkworm Sync Tests
  file(GLOB_RECURSE SILKWORM_SYNC_TESTS CONFIGURE_DEPENDS "${SILKWORM_MAIN_SRC_DIR}/sync/*_test.cpp")
  add_executable(sync_test unit_test.cpp ${SILKWORM_SYNC_TESTS})
  target_link_libraries(sync_test silkworm_node silkworm_sync Catch2::Catch2 GTest::gmock)

  # Ethereum EL Tests (https://github.com/ethereum/tests)
  find_package(CLI11 REQUIRED)
  add_executable(ethereum ethereum.cpp)
  target_compile_definitions(
    ethereum PRIVATE SILKWORM_ETHEREUM_TESTS_DIR="${SILKWORM_MAIN_DIR}/third_party/ethereum-tests"
  )
  target_link_libraries(ethereum PRIVATE silkworm_infra evmc::loader CLI11::CLI11 magic_enum::magic_enum)

  # BE&KV Tests
  add_executable(backend_kv_test "backend_kv_test.cpp" "../common/shutdown_signal.hpp" "../common/shutdown_signal.cpp")
  target_link_libraries(backend_kv_test PRIVATE silkworm_node CLI11::CLI11 magic_enum::magic_enum)

  add_executable(sentry_client_test "sentry_client_test.cpp")
  target_link_libraries(sentry_client_test PRIVATE silkworm_sentry)
endif()
