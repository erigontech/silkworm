// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>

#include <silkworm/core/types/bloom.hpp>
#include <silkworm/core/types/log.hpp>
#include <silkworm/core/types/transaction.hpp>

namespace silkworm {

struct Receipt {
    TransactionType type{TransactionType::kLegacy};
    bool success{false};
    uint64_t cumulative_gas_used{0};
    Bloom bloom{};
    std::vector<Log> logs;
};

namespace rlp {
    void encode(Bytes& to, const Receipt&);
}

}  // namespace silkworm
