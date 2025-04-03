# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

include("${SILKWORM_MAIN_DIR}/cmake/common/targets.cmake")

find_package(absl REQUIRED)
find_package(CLI11 REQUIRED)
find_package(nlohmann_json REQUIRED)

set(LIBS_PUBLIC "")

# cmake-format: off
set(LIBS_PRIVATE
    CLI11::CLI11
    absl::time
    ethash::keccak
    nlohmann_json::nlohmann_json
    silkworm_core
    silkworm_sentry
)
# cmake-format: on

silkworm_library(
  silkworm_dev
  PUBLIC ${LIBS_PUBLIC}
  PRIVATE ${LIBS_PRIVATE}
)

# silkworm_dev_cli depends on silkworm_dev
add_subdirectory(cli)
