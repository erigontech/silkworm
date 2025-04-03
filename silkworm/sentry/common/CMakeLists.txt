# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

include("${SILKWORM_MAIN_DIR}/cmake/common/targets.cmake")

find_package(Boost REQUIRED COMPONENTS headers)

silkworm_library(silkworm_sentry_common PUBLIC Boost::headers silkworm_core silkworm_infra)
