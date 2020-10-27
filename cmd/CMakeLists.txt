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

find_package(absl CONFIG REQUIRED)
find_package(Boost CONFIG REQUIRED COMPONENTS filesystem log thread)

if(MSVC)
  add_link_options(/STACK:10000000)
elseif (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  add_link_options(-Wl,-stack_size -Wl,0x1000000)
endif()

add_executable(check_changes check_changes.cpp)
target_link_libraries(check_changes PRIVATE silkworm absl::flags_parse absl::time Boost::filesystem)

find_package(CLI11 CONFIG REQUIRED)

add_executable(check_senders check_senders.cpp)
target_link_libraries(check_senders PRIVATE silkworm Boost::filesystem CLI11::CLI11)

add_executable(dbtool dbtool.cpp)
target_link_libraries(dbtool PRIVATE silkworm Boost::filesystem CLI11::CLI11)

add_executable(execute execute.cpp)
target_link_libraries(execute PRIVATE silkworm CLI11::CLI11 Boost::log Boost::thread)

# Ethereum Consensus Tests
find_package(nlohmann_json CONFIG REQUIRED)
add_compile_definitions(SILKWORM_CONSENSUS_TEST_DIR="${CMAKE_SOURCE_DIR}/tests")
add_executable(consensus consensus.cpp)
target_link_libraries(consensus PRIVATE silkworm nlohmann_json::nlohmann_json Boost::filesystem)

# Unit tests
enable_testing()

find_package(Catch2 CONFIG REQUIRED)

file(GLOB_RECURSE SILKWORM_TESTS CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/silkworm/*_test.cpp")
add_executable(unit_test unit_test.cpp ${SILKWORM_TESTS})
target_link_libraries(unit_test silkworm Catch2::Catch2)

include(CTest)
include(Catch)
catch_discover_tests(unit_test)

# Benchmarks
find_package(benchmark CONFIG REQUIRED)
add_executable(benchmark_precompile benchmark_precompile.cpp)
target_link_libraries(benchmark_precompile silkworm benchmark::benchmark)
