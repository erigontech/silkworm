// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/hash_maps.hpp>
#include <silkworm/core/types/account.hpp>

namespace silkworm::state {

struct Object {
    std::optional<Account> initial;
    std::optional<Account> current;
};

struct CommittedValue {
    evmc::bytes32 initial{};   // value at the beginning of the block
    evmc::bytes32 original{};  // value at the beginning of the transaction; see EIP-2200
};

struct Storage {
    FlatHashMap<evmc::bytes32, CommittedValue> committed;
    FlatHashMap<evmc::bytes32, evmc::bytes32> current;
};

}  // namespace silkworm::state
