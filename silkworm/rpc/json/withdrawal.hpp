// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <nlohmann/json.hpp>

#include <silkworm/core/types/withdrawal.hpp>
#include <silkworm/rpc/json/glaze.hpp>
#include <silkworm/rpc/types/block.hpp>

namespace silkworm::rpc {

struct GlazeJsonWithdrawals {
    char index[kInt64HexSize]{};
    char validator_index[kInt64HexSize]{};
    char address[kAddressHexSize]{};
    char amount[kInt64HexSize]{};

    struct glaze {
        using T = GlazeJsonWithdrawals;
        // NOLINTNEXTLINE(readability-identifier-naming)
        static constexpr auto value = glz::object(
            "index", &T::index,
            "validatorIndex", &T::validator_index,
            "address", &T::address,
            "amount", &T::amount);
    };
};

std::optional<std::vector<GlazeJsonWithdrawals>> make_glaze_json_withdrawals(const BlockBody& block);

}  // namespace silkworm::rpc

namespace silkworm {

void to_json(nlohmann::json& json, const Withdrawal& withdrawal);
void from_json(const nlohmann::json& json, Withdrawal& withdrawal);

}  // namespace silkworm
