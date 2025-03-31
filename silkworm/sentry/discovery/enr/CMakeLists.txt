# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

include("${SILKWORM_MAIN_DIR}/cmake/common/targets.cmake")

silkworm_library(
  silkworm_sentry_discovery_enr
  PUBLIC silkworm_sentry_common silkworm_core silkworm_sentry_discovery_common
  PRIVATE cpp_base64 silkworm_infra
)
