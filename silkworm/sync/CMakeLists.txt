# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

include("${SILKWORM_MAIN_DIR}/cmake/common/targets.cmake")

find_package(absl REQUIRED)
find_package(GTest REQUIRED)
find_package(magic_enum REQUIRED)

set(SILKWORM_SYNC_PUBLIC_LIBS
    absl::btree
    absl::flat_hash_map
    absl::flat_hash_set
    mdbx-static
    silkworm_core
    silkworm_execution
    silkworm_rpcdaemon
    silkworm_sentry
)

# cmake-format: off
set(SILKWORM_SYNC_PRIVATE_LIBS
    cborcpp
    evmone
    magic_enum::magic_enum
)
# cmake-format: on

silkworm_library(
  silkworm_sync
  PUBLIC ${SILKWORM_SYNC_PUBLIC_LIBS}
  PRIVATE ${SILKWORM_SYNC_PRIVATE_LIBS}
)

target_link_libraries(
  silkworm_sync_test PRIVATE GTest::gmock silkworm_db_test_util silkworm_infra_test_util silkworm_rpcdaemon_test_util
)
