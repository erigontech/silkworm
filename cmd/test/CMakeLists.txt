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

if(NOT SILKWORM_WASM_API)
  set(CORE_TEST_ABSEIL_ENABLED TRUE)
endif()

if(CORE_TEST_ABSEIL_ENABLED)
  if(NOT CONAN_PACKAGE_MANAGER)
    hunter_add_package(abseil)
  endif()
  find_package(absl REQUIRED)
endif()

find_package(Catch2 REQUIRED)
find_package(Microsoft.GSL REQUIRED)

# Silkworm Core Tests
file(GLOB_RECURSE SILKWORM_CORE_TESTS CONFIGURE_DEPENDS "${SILKWORM_MAIN_SRC_DIR}/core/*_test.cpp")
add_executable(core_test unit_test.cpp ${SILKWORM_CORE_TESTS})

set(CORE_TEST_LIBS
  silkworm_core
  Catch2::Catch2
  evmone
)

if(CORE_TEST_ABSEIL_ENABLED)
  list(APPEND CORE_TEST_LIBS
    absl::flat_hash_map
    absl::flat_hash_set
    absl::node_hash_map
  )
endif()

target_link_libraries(core_test ${CORE_TEST_LIBS})

if(MSVC)
  target_compile_options(core_test PRIVATE /EHa- /EHsc)
else()
  target_compile_options(core_test PRIVATE -fno-exceptions)
endif()

if(NOT SILKWORM_CORE_ONLY)
  find_package(asio-grpc REQUIRED)
  find_package(GTest REQUIRED)

  # Silkworm Infra Tests
  file(GLOB_RECURSE SILKWORM_INFRA_TESTS CONFIGURE_DEPENDS "${SILKWORM_MAIN_SRC_DIR}/infra/*_test.cpp")
  add_executable(infra_test "unit_test.cpp;${SILKWORM_INFRA_TESTS}")
  if(SILKWORM_SANITIZE)
    target_compile_definitions(infra_test PRIVATE GRPC_ASAN_SUPPRESSED GRPC_TSAN_SUPPRESSED)
  endif()
  target_link_libraries(infra_test silkworm_infra Catch2::Catch2)

  # Silkworm Node Tests
  file(GLOB_RECURSE SILKWORM_NODE_TESTS CONFIGURE_DEPENDS "${SILKWORM_MAIN_SRC_DIR}/node/*_test.cpp")
  add_executable(node_test unit_test.cpp ${SILKWORM_NODE_TESTS})
  if(SILKWORM_SANITIZE)
    target_compile_definitions(node_test PRIVATE GRPC_ASAN_SUPPRESSED GRPC_TSAN_SUPPRESSED)
  endif()
  target_link_libraries(node_test silkworm_node Catch2::Catch2)

  # Silkworm RpcDaemon Tests
  file(GLOB_RECURSE SILKWORM_RPCDAEMON_TESTS CONFIGURE_DEPENDS "${SILKWORM_MAIN_SRC_DIR}/silkrpc/*_test.cpp")
  add_executable(rpcdaemon_test unit_test.cpp ${SILKWORM_RPCDAEMON_TESTS})
  if(SILKWORM_SANITIZE)
    target_compile_definitions(rpcdaemon_test PRIVATE GRPC_ASAN_SUPPRESSED GRPC_TSAN_SUPPRESSED)
  endif()
  target_include_directories(rpcdaemon_test PRIVATE
          ${SILKWORM_MAIN_DIR}
          ${SILKWORM_MAIN_DIR}/third_party/evmone/evmc/include)
  target_link_libraries(rpcdaemon_test silkworm_node silkrpc asio-grpc::asio-grpc Catch2::Catch2 GTest::gmock)

  # Silkworm Sentry Tests
  file(GLOB_RECURSE SENTRY_TEST_FILES CONFIGURE_DEPENDS "${SILKWORM_MAIN_SRC_DIR}/sentry/*_test.cpp")
  add_executable(sentry_test unit_test.cpp ${SENTRY_TEST_FILES})
  if(SILKWORM_SANITIZE)
    target_compile_definitions(sentry_test PRIVATE GRPC_ASAN_SUPPRESSED GRPC_TSAN_SUPPRESSED)
  endif()
  target_link_libraries(sentry_test silkworm_sentry Catch2::Catch2 Microsoft.GSL::GSL)

  # Silkworm Sync Tests
  file(GLOB_RECURSE SILKWORM_SYNC_TESTS CONFIGURE_DEPENDS "${SILKWORM_MAIN_SRC_DIR}/sync/*_test.cpp")
  add_executable(sync_test unit_test.cpp ${SILKWORM_SYNC_TESTS})
  if(SILKWORM_SANITIZE)
    target_compile_definitions(sync_test PRIVATE GRPC_ASAN_SUPPRESSED GRPC_TSAN_SUPPRESSED)
  endif()
  target_link_libraries(sync_test silkworm_node silkworm_sync Catch2::Catch2)

  # Ethereum Consensus Tests
  if(NOT CONAN_PACKAGE_MANAGER)
    hunter_add_package(CLI11)
  endif()
  find_package(CLI11 REQUIRED)
  add_executable(consensus consensus.cpp)
  target_compile_definitions(consensus PRIVATE SILKWORM_CONSENSUS_TEST_DIR="${CMAKE_SOURCE_DIR}/third_party/tests")
  target_link_libraries(consensus PRIVATE silkworm_node evmc::loader CLI11::CLI11)

  file(GLOB_RECURSE CMD_COMMON_SRC CONFIGURE_DEPENDS
    "../common/shutdown_signal.hpp"
    "../common/shutdown_signal.cpp"
  )

  # BE&KV Tests
  add_executable(backend_kv_test "backend_kv_test.cpp;${CMD_COMMON_SRC}")
  target_link_libraries(backend_kv_test PRIVATE silkworm_node CLI11::CLI11)

  add_executable(sentry_client_test "sentry_client_test.cpp")
  target_link_libraries(sentry_client_test PRIVATE silkworm_sentry)
endif()
