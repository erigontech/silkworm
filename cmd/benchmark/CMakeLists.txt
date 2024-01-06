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

find_package(benchmark REQUIRED)


file(GLOB_RECURSE SILKWORM_BENCHMARK_TESTS CONFIGURE_DEPENDS "${SILKWORM_MAIN_SRC_DIR}/*_benchmark.cpp")
add_executable(benchmark_test benchmark_test.cpp ${SILKWORM_BENCHMARK_TESTS})
target_link_libraries(benchmark_test silkworm_infra silkworm_node silkworm_rpcdaemon benchmark::benchmark)
