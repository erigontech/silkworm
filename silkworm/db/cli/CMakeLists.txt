# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

include("${SILKWORM_MAIN_DIR}/cmake/common/targets.cmake")

find_package(Boost REQUIRED COMPONENTS headers)
find_package(CLI11 REQUIRED)

set(LIBS_PUBLIC silkworm_db silkworm_infra_cli Boost::headers CLI11::CLI11)

# cmake-format: off
set(LIBS_PRIVATE
    silkworm-buildinfo
)
# cmake-format: on

silkworm_library(
  silkworm_db_cli
  PUBLIC ${LIBS_PUBLIC}
  PRIVATE ${LIBS_PRIVATE}
)
