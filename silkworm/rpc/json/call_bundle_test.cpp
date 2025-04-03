// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "call_bundle.hpp"

#include <catch2/catch_test_macros.hpp>
#include <evmc/evmc.hpp>
#include <intx/intx.hpp>

namespace silkworm::rpc {

TEST_CASE("serialize empty call_bundle", "[rpc][to_json]") {
    struct CallBundleInfo bundle_info {};

    nlohmann::json j = bundle_info;
    CHECK(j == R"({
        "bundleHash":"0x0000000000000000000000000000000000000000000000000000000000000000",
        "results":[]
    })"_json);
}

TEST_CASE("serialize call_bundle with error", "[rpc][to_json]") {
    struct CallBundleInfo bundle_info {};
    struct CallBundleTxInfo tx_info {};
    tx_info.gas_used = 0x234;
    tx_info.error_message = "operation reverted";
    bundle_info.txs_info.push_back(tx_info);

    nlohmann::json j = bundle_info;
    CHECK(j == R"({
        "bundleHash":"0x0000000000000000000000000000000000000000000000000000000000000000",
        "results":[{"error": "operation reverted", "gasUsed": 564,
                    "txHash": "0x0000000000000000000000000000000000000000000000000000000000000000"}]
    })"_json);
}

TEST_CASE("serialize call_bundle with value", "[rpc][to_json]") {
    struct CallBundleInfo bundle_info {};
    struct CallBundleTxInfo tx_info {};
    tx_info.gas_used = 0x234;
    tx_info.value = 0x1230000000000000000000000000000000000000000000000000000000000321_bytes32;
    bundle_info.txs_info.push_back(tx_info);

    nlohmann::json j = bundle_info;
    CHECK(j == R"({
        "bundleHash":"0x0000000000000000000000000000000000000000000000000000000000000000",
        "results":[{"value": "0x1230000000000000000000000000000000000000000000000000000000000321", "gasUsed": 564,
                    "txHash": "0x0000000000000000000000000000000000000000000000000000000000000000"}]
    })"_json);
}

}  // namespace silkworm::rpc
