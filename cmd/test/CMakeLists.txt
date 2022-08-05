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

find_package(Catch2 CONFIG REQUIRED)
find_package(Microsoft.GSL CONFIG REQUIRED)

# Silkworm Core Tests
file(GLOB_RECURSE SILKWORM_CORE_TESTS CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/core/silkworm/*_test.cpp")
add_executable(core_test unit_test.cpp ${SILKWORM_CORE_TESTS})
target_link_libraries(core_test silkworm_core Catch2::Catch2 evmone)
if(MSVC)
  target_compile_options(core_test PRIVATE /EHa- /EHsc)
else()
  target_compile_options(core_test PRIVATE -fno-exceptions)
endif()

if(NOT SILKWORM_CORE_ONLY)
  # Silkworm Node Tests
  file(GLOB_RECURSE SILKWORM_NODE_TESTS CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/node/silkworm/*_test.cpp")
  add_executable(node_test unit_test.cpp ${SILKWORM_NODE_TESTS})
  if(SILKWORM_SANITIZE)
    target_compile_definitions(node_test PRIVATE GRPC_ASAN_SUPPRESSED GRPC_TSAN_SUPPRESSED)
  endif()
  target_link_libraries(node_test silkworm_node Catch2::Catch2)

  # Ethereum Consensus Tests
  hunter_add_package(CLI11)
  find_package(CLI11 CONFIG REQUIRED)
  add_executable(consensus consensus.cpp)
  target_compile_definitions(consensus PRIVATE SILKWORM_CONSENSUS_TEST_DIR="${CMAKE_SOURCE_DIR}/third_party/tests")
  target_link_libraries(consensus PRIVATE silkworm_node evmc::loader CLI11::CLI11)

  # BE&KV Tests
  add_executable(backend_kv_test backend_kv_test.cpp)
  target_link_libraries(backend_kv_test PRIVATE silkworm_node CLI11::CLI11)

  # Sentry Tests
  file(GLOB_RECURSE SENTRY_TEST_FILES CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/sentry/*_test.cpp")
  add_executable(sentry_test unit_test.cpp ${SENTRY_TEST_FILES})
  if(SILKWORM_SANITIZE)
    target_compile_definitions(sentry_test PRIVATE GRPC_ASAN_SUPPRESSED GRPC_TSAN_SUPPRESSED)
  endif()
  target_link_libraries(sentry_test
    silkworm_sentry
    silkworm_node
    Catch2::Catch2
    Microsoft.GSL::GSL
  )

endif()
