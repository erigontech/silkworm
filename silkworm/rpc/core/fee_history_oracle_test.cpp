// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "fee_history_oracle.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/test_util/log.hpp>

namespace silkworm::rpc::fee_history {

TEST_CASE("FeeHistory: json serialization") {
    SECTION("default value") {
        FeeHistory fh;

        CHECK(nlohmann::json(fh) == R"({
            "gasUsedRatio":null,
            "blobGasUsedRatio":null,
            "oldestBlock":"0x0"
        })"_json);
    }

    SECTION("built value") {
        FeeHistory fh{
            0x867a80,
            {0x13c723946e, 0x163fe26534},
            {0.9998838666666666},
            {{0x59682f00, 0x9502f900}}};

        CHECK(nlohmann::json(fh) == R"({
            "baseFeePerGas":["0x13c723946e","0x163fe26534"],
            "blobGasUsedRatio":null,
            "blobGasUsedRatio":null,
            "gasUsedRatio":[0.9998838666666666],
            "oldestBlock":"0x867a80",
            "reward":[
                ["0x59682f00","0x9502f900"]
            ]
        })"_json);
    }
}
}  // namespace silkworm::rpc::fee_history
