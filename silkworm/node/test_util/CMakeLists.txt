# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

include("${SILKWORM_MAIN_DIR}/cmake/common/targets.cmake")

find_package(Boost REQUIRED COMPONENTS headers)
find_package(GTest REQUIRED)

silkworm_library(
  silkworm_node_test_util
  PUBLIC silkworm_infra silkworm_node
  PRIVATE silkworm_db_test_util Boost::headers glaze::glaze GTest::gmock
)
