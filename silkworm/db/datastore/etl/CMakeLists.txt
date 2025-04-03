# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

include("${SILKWORM_MAIN_DIR}/cmake/common/targets.cmake")

silkworm_library(
  silkworm_datastore_etl
  PUBLIC silkworm_core
  PRIVATE silkworm_infra
)
