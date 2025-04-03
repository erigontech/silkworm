# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

include("${SILKWORM_MAIN_DIR}/cmake/common/targets.cmake")

add_subdirectory(common)
add_subdirectory(etl)
add_subdirectory(kvdb)
add_subdirectory(snapshots)

find_package(Boost REQUIRED COMPONENTS headers)

# cmake-format: off
set(LIBS_PUBLIC
    Boost::headers
    silkworm_core
    silkworm_infra
    silkworm_datastore_common
    silkworm_datastore_kvdb
    silkworm_snapshots
)
# cmake-format: on

# cmake-format: off
set(LIBS_PRIVATE
)
# cmake-format: on

silkworm_library(
  silkworm_datastore
  PUBLIC ${LIBS_PUBLIC}
  PRIVATE ${LIBS_PRIVATE}
)
