// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <CLI/CLI.hpp>

#include <silkworm/db/datastore/snapshots/snapshot_settings.hpp>

namespace silkworm::cmd::common {

//! \brief Setup options to populate snapshot settings after cli.parse()
void add_snapshot_options(CLI::App& cli, snapshots::SnapshotSettings& snapshot_settings);

}  // namespace silkworm::cmd::common
