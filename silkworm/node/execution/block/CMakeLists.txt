# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

include("${SILKWORM_MAIN_DIR}/cmake/common/targets.cmake")

# cmake - format : off
set(LIBS_PRIVATE silkworm_core silkworm_db silkworm_infra)
# cmake - format : on

silkworm_library(silkworm_block_execution PRIVATE ${LIBS_PRIVATE})
