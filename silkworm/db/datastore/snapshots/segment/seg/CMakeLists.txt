# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

include("${SILKWORM_MAIN_DIR}/cmake/common/targets.cmake")

# circular_buffer, iostreams (for fsync)
find_package(Boost REQUIRED COMPONENTS headers iostreams)

silkworm_library(
  silkworm_snapshots_seg
  PUBLIC silkworm_core silkworm_infra
  PRIVATE Boost::headers Boost::iostreams sais_lite silkworm_datastore_etl
)
