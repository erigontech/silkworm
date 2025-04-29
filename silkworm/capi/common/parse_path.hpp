// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <filesystem>

#include "preamble.h"

namespace silkworm::capi {

//! Build a file system path from its C null-terminated upper-bounded representation
std::filesystem::path parse_path(const char path[SILKWORM_PATH_SIZE]);

}  // namespace silkworm::capi
