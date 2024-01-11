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

#include "fee_history_oracle.hpp"

#include <catch2/catch.hpp>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/test_util/log.hpp>

namespace silkworm::rpc::fee_history {

TEST_CASE("FeeHistory: json serialization") {
    silkworm::test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};

    SECTION("default value") {
        FeeHistory fh;

        CHECK(nlohmann::json(fh) == R"({
            "gasUsedRatio":null,
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
            "gasUsedRatio":[0.9998838666666666],
            "oldestBlock":"0x867a80",
            "reward":[
                ["0x59682f00","0x9502f900"]
            ]
        })"_json);
    }
}
}  // namespace silkworm::rpc::fee_history
