# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

find_package(Boost REQUIRED COMPONENTS headers)

include("${SILKWORM_MAIN_DIR}/cmake/common/targets.cmake")

silkworm_library(silkworm_sentry_discovery_common PUBLIC silkworm_core Boost::headers)
