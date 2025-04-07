# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

set(TARGET silkworm_sentry_cli)

find_package(CLI11 REQUIRED)

file(GLOB_RECURSE SRC CONFIGURE_DEPENDS "*.cpp" "*.hpp")

add_library(${TARGET} ${SRC})

target_link_libraries(${TARGET} PUBLIC silkworm_core silkworm_infra silkworm_sentry silkworm_infra_cli CLI11::CLI11)
