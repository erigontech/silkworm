// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>
#include <string>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/types/hash.hpp>

#include "status.hpp"

namespace silkworm::execution::api {

struct ForkChoice {
    Hash head_block_hash;
    uint64_t timeout{0};
    std::optional<Hash> finalized_block_hash;
    std::optional<Hash> safe_block_hash;
};

struct ForkChoiceResult {
    ExecutionStatus status{ExecutionStatus::kSuccess};
    Hash latest_valid_head;
    std::string validation_error;

    explicit operator bool() const { return success(status); }
};

}  // namespace silkworm::execution::api
