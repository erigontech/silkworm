/*
   Copyright 2023 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include "call_bundle.hpp"

#include <catch2/catch.hpp>
#include <evmc/evmc.hpp>
#include <intx/intx.hpp>

#include <silkworm/rpc/json/call_bundle.hpp>
#include <silkworm/rpc/json/types.hpp>

namespace silkworm::rpc {

using Catch::Matchers::Message;
using evmc::literals::operator""_address, evmc::literals::operator""_bytes32;

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
