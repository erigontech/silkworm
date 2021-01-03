#[[
   Copyright 2020 The Silkworm Authors

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

if(MSVC)
  add_link_options(/STACK:10000000)
elseif (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  add_link_options(-Wl,-stack_size -Wl,0x1000000)
endif()

file(GLOB_RECURSE SILKWORM_CORE_TESTS CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/core/silkworm/*_test.cpp")
add_executable(core_test unit_test.cpp ${SILKWORM_CORE_TESTS})
target_link_libraries(core_test silkworm_core Catch2::Catch2)
target_compile_definitions(core_test PRIVATE CATCH_CONFIG_NO_POSIX_SIGNALS) # Wasm compatibility
if(MSVC)
  target_compile_options(core_test PRIVATE /EHsc)
else()
  target_compile_options(core_test PRIVATE -fno-exceptions)
endif()

find_package(absl CONFIG REQUIRED)
find_package(Boost CONFIG REQUIRED COMPONENTS filesystem)

file(GLOB_RECURSE SILKWORM_DB_TESTS CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/db/silkworm/*_test.cpp")
add_executable(db_test unit_test.cpp ${SILKWORM_DB_TESTS})
target_link_libraries(db_test silkworm_db Catch2::Catch2)

add_executable(check_changes check_changes.cpp)
target_link_libraries(check_changes PRIVATE silkworm_db absl::flags_parse absl::time Boost::filesystem)

add_executable(scan_txs scan_txs.cpp)
target_link_libraries(scan_txs PRIVATE silkworm_db absl::flags_parse absl::time Boost::filesystem)

find_package(CLI11 CONFIG REQUIRED)

add_executable(check_senders check_senders.cpp)
target_link_libraries(check_senders PRIVATE silkworm_db CLI11::CLI11 Boost::filesystem)

add_executable(dbtool dbtool.cpp)
target_link_libraries(dbtool PRIVATE silkworm_db CLI11::CLI11 Boost::filesystem)

add_executable(execute execute.cpp)
target_link_libraries(execute PRIVATE silkworm_db silkworm_tg_api CLI11::CLI11 Boost::filesystem)
target_include_directories(execute PRIVATE ${CMAKE_SOURCE_DIR})

# Ethereum Consensus Tests
find_package(nlohmann_json CONFIG REQUIRED)
add_executable(consensus consensus.cpp)
target_compile_definitions(consensus PRIVATE SILKWORM_CONSENSUS_TEST_DIR="${CMAKE_SOURCE_DIR}/tests")
target_link_libraries(consensus PRIVATE silkworm_core nlohmann_json::nlohmann_json Boost::filesystem)

# Benchmarks
find_package(benchmark CONFIG REQUIRED)
add_executable(benchmark_precompile benchmark_precompile.cpp)
target_link_libraries(benchmark_precompile silkworm_core benchmark::benchmark)
