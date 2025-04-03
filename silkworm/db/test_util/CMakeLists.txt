# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

include("${SILKWORM_MAIN_DIR}/cmake/common/targets.cmake")

find_package(GTest REQUIRED)
find_package(nlohmann_json REQUIRED)

silkworm_library(
  silkworm_db_test_util
  PUBLIC silkworm_core silkworm_infra silkworm_db GTest::gmock
  PRIVATE nlohmann_json::nlohmann_json
)
