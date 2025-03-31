# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

find_package(benchmark REQUIRED)

file(GLOB_RECURSE SILKWORM_BENCHMARK_TESTS CONFIGURE_DEPENDS "${SILKWORM_MAIN_SRC_DIR}/*_benchmark.cpp")
add_executable(benchmark_test benchmark_test.cpp ${SILKWORM_BENCHMARK_TESTS})
target_link_libraries(
  benchmark_test
  silkworm_infra
  silkworm_infra_test_util
  silkworm_node
  silkworm_rpcdaemon
  silkworm_rpcdaemon_test_util
  benchmark::benchmark
)
