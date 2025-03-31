// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>
#include <set>
#include <string>
#include <variant>

#include <silkworm/core/types/block_id.hpp>
#include <silkworm/core/types/hash.hpp>

namespace silkworm::execution::api {

struct ValidChain {
    BlockId current_head;
};

struct InvalidChain {
    BlockId unwind_point;
    std::optional<Hash> bad_block;
    std::set<Hash> bad_headers;
};

struct ValidationError {
    BlockId latest_valid_head;
    std::string error;
};

using ValidationResult = std::variant<ValidChain, InvalidChain, ValidationError>;
using VerificationResult = ValidationResult;

}  // namespace silkworm::execution::api
