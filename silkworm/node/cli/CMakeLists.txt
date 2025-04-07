# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

include("${SILKWORM_MAIN_DIR}/cmake/common/targets.cmake")

find_package(CLI11 REQUIRED)

set(LIBS_PUBLIC silkworm_core silkworm_node silkworm_infra_cli CLI11::CLI11)

silkworm_library(silkworm_node_cli PUBLIC ${LIBS_PUBLIC})
