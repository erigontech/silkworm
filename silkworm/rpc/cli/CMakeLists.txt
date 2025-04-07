# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

include("${SILKWORM_MAIN_DIR}/cmake/common/targets.cmake")

find_package(absl REQUIRED)
find_package(CLI11 REQUIRED)

set(LIBS_PUBLIC
    silkworm_core
    silkworm_rpcdaemon
    silkworm_infra_cli
    Boost::headers
    absl::strings
    CLI11::CLI11
)

silkworm_library(silkworm_rpcdaemon_cli PUBLIC ${LIBS_PUBLIC})
