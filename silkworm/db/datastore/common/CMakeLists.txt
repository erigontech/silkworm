# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

include("${SILKWORM_MAIN_DIR}/cmake/common/targets.cmake")

find_package(absl REQUIRED COMPONENTS flat_hash_map)

silkworm_library(
  silkworm_datastore_common
  PUBLIC silkworm_core absl::flat_hash_map
  PRIVATE ""
)
