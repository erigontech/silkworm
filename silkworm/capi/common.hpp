// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <filesystem>

#include <silkworm/infra/common/log.hpp>

#include "silkworm.h"

//! Build a file system path from its C null-terminated upper-bounded representation
std::filesystem::path parse_path(const char path[SILKWORM_PATH_SIZE]);

//! Build log configuration matching Erigon log format w/ custom verbosity level
silkworm::log::Settings make_log_settings(SilkwormLogLevel c_log_level);
