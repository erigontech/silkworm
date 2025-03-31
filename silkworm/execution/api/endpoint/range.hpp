// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <vector>

#include "block.hpp"

namespace silkworm::execution::api {

using BlockHashes = std::vector<Hash>;
using BlockBodies = std::vector<Body>;
using BlockHeaders = std::vector<BlockHeader>;

}  // namespace silkworm::execution::api
