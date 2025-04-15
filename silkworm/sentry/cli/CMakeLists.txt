# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

add_library(silkworm_sentry_cli "sentry_options.cpp")
target_link_libraries(silkworm_sentry_cli PUBLIC silkworm_sentry silkworm_infra_cli)
