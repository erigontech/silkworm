// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>
#include <vector>

#include <silkworm/core/types/block.hpp>

#include "status.hpp"

namespace silkworm::execution::api {

using Blocks = std::vector<std::shared_ptr<Block>>;

struct InsertionResult {
    ExecutionStatus status;

    explicit operator bool() const { return success(status); }
};

}  // namespace silkworm::execution::api
