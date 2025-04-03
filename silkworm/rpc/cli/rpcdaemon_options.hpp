// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <CLI/CLI.hpp>

#include <silkworm/rpc/daemon.hpp>

namespace silkworm::cmd::common {

void add_rpcdaemon_options(CLI::App& cli, silkworm::rpc::DaemonSettings& settings);

}  // namespace silkworm::cmd::common
