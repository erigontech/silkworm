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

#include "bor_config.hpp"

#include <catch2/catch.hpp>

namespace silkworm::protocol {

TEST_CASE("BorConfig JSON") {
    const auto json = nlohmann::json::parse(R"({    
            "sprint": {
                "0": 64,
                "38189056": 16
            },
            "jaipurBlock": 123
        })");

    const std::optional<BorConfig> config{BorConfig::from_json(json)};

    REQUIRE(config);
    CHECK(config == BorConfig{
                        .sprint = {
                            {0, 64},
                            {38189056, 16},
                        },
                        .jaipur_block = 123,
                    });
    CHECK(config->to_json() == json);
}

}  // namespace silkworm::protocol
