// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <set>
#include <variant>
#include <vector>

#include <silkworm/core/types/block.hpp>

namespace silkworm::execution {

using BlockVector = std::vector<std::shared_ptr<Block>>;

struct ForkChoiceApplication {
    bool success{false};  // Fork choice is either successful or unsuccessful.
    Hash current_head;    // Return latest valid hash in case of halt of execution.
    BlockNum current_block_num{0};
};

struct ValidChain {
    Hash current_head;
};

struct InvalidChain {
    Hash latest_valid_head;
    std::optional<Hash> bad_block;
    std::set<Hash> bad_headers;
};

struct ValidationError {
    Hash latest_valid_head;
    std::string error;
};

using ValidationResult = std::variant<ValidChain, InvalidChain, ValidationError>;

}  // namespace silkworm::execution
