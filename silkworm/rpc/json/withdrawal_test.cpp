// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "withdrawal.hpp"

#include <catch2/catch_test_macros.hpp>
#include <evmc/evmc.hpp>

namespace silkworm {

using evmc::literals::operator""_address;

TEST_CASE("serialize WithdrawalV1", "[silkworm::json][to_json]") {
    Withdrawal withdrawal{
        .index = 6,
        .validator_index = 12,
        .address = 0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b_address,
        .amount = 10'000};
    CHECK(nlohmann::json(withdrawal) == R"({
        "index":"0x6",
        "validatorIndex":"0xc",
        "address":"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b",
        "amount":"0x2710"
    })"_json);
}

}  // namespace silkworm
