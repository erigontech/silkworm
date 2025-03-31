// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <CLI/CLI.hpp>

#include <silkworm/node/common/node_settings.hpp>

namespace silkworm::cmd::common {

void add_node_options(CLI::App& cli, NodeSettings& settings);

}  // namespace silkworm::cmd::common
