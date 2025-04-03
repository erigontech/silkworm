# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

find_package(Boost REQUIRED COMPONENTS headers)
find_package(SQLiteCpp REQUIRED)

include("${SILKWORM_MAIN_DIR}/cmake/common/targets.cmake")

silkworm_library(
  silkworm_sentry_node_db
  PUBLIC silkworm_core silkworm_infra silkworm_sentry_common silkworm_sentry_discovery_common
  PRIVATE Boost::headers SQLiteCpp
)

target_link_libraries(silkworm_sentry_node_db_test INTERFACE silkworm_infra_test_util)
