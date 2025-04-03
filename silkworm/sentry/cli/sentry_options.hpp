// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <CLI/CLI.hpp>

#include <silkworm/sentry/settings.hpp>

namespace silkworm::cmd::common {

void add_sentry_options(CLI::App& cli, silkworm::sentry::Settings& settings);

}  // namespace silkworm::cmd::common
