# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

find_package(Boost REQUIRED COMPONENTS headers)

include("${SILKWORM_MAIN_DIR}/cmake/common/targets.cmake")

silkworm_library(
  silkworm_sentry_disc_v4
  PUBLIC silkworm_infra silkworm_sentry_common silkworm_sentry_node_db silkworm_sentry_discovery_enr
  PRIVATE Boost::headers stbrumme_keccak silkworm_core silkworm_sentry_discovery_common
)
