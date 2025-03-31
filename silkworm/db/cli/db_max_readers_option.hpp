// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <CLI/CLI.hpp>

namespace silkworm::cmd::common {

//! \brief Set up option for maximum number of database readers
void add_option_db_max_readers(CLI::App& cli, uint32_t& max_readers);

}  // namespace silkworm::cmd::common
