# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

include("${SILKWORM_MAIN_DIR}/cmake/common/targets.cmake")

add_subdirectory(bittorrent)
add_subdirectory(segment/seg)

find_package(absl REQUIRED COMPONENTS strings)
find_package(Boost REQUIRED COMPONENTS headers url) # headers for signals2
find_package(Microsoft.GSL REQUIRED)
find_package(OpenSSL REQUIRED)

# cmake-format: off
set(LIBS_PRIVATE
    absl::strings
    Boost::headers
    OpenSSL::Crypto
    silkworm_snapshots_seg
)
# cmake-format: on

# cmake-format: off
set(LIBS_PUBLIC
    Microsoft.GSL::GSL
    silkworm_core
    silkworm_infra
    silkworm_datastore_common
    silkworm_bittorrent
)
# cmake-format: on

silkworm_library(
  silkworm_snapshots
  PUBLIC ${LIBS_PUBLIC}
  PRIVATE ${LIBS_PRIVATE}
)

target_link_libraries(silkworm_snapshots_test PRIVATE silkworm_infra_test_util)
