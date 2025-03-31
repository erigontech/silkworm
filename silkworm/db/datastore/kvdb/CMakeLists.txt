# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

include("${SILKWORM_MAIN_DIR}/cmake/common/targets.cmake")

find_package(absl REQUIRED)
find_package(roaring REQUIRED)

silkworm_library(
  silkworm_datastore_kvdb
  PUBLIC absl::btree
         absl::function_ref
         roaring::roaring
         mdbx-static
         silkworm_core
         silkworm_infra
         silkworm_datastore_common
         silkworm_datastore_etl
)

target_link_libraries(silkworm_datastore_kvdb_test PRIVATE silkworm_infra_test_util)
