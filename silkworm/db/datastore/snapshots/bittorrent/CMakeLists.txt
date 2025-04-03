# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

include("${SILKWORM_MAIN_DIR}/cmake/common/targets.cmake")

find_package(absl REQUIRED COMPONENTS strings)
find_package(Boost REQUIRED COMPONENTS headers url)
find_package(GTest REQUIRED)
find_package(LibtorrentRasterbar REQUIRED)
find_package(magic_enum REQUIRED)

# cmake-format: off
set(LIBS_PRIVATE
    absl::strings
    LibtorrentRasterbar::torrent-rasterbar
    magic_enum::magic_enum
)
# cmake-format: on

# cmake-format: off
set(LIBS_PUBLIC
    Boost::headers
    Boost::url
    silkworm_core
    silkworm_infra
)
# cmake-format: on

silkworm_library(
  silkworm_bittorrent
  PUBLIC ${LIBS_PUBLIC}
  PRIVATE ${LIBS_PRIVATE}
)

target_link_libraries(silkworm_bittorrent_test PRIVATE GTest::gmock silkworm_infra_test_util)
