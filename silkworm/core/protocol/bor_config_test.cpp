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

#include <string_view>

#include <catch2/catch.hpp>

namespace silkworm::protocol {

TEST_CASE("BorConfig JSON") {
    const auto json = nlohmann::json::parse(R"({
            "period": {
                "0": 2,
                "25275000": 5,
                "29638656": 2
            },
            "sprint": {
                "0": 64,
                "38189056": 16
            },
            "jaipurBlock": 123
        })");

    const std::optional<BorConfig> config{BorConfig::from_json(json)};

    REQUIRE(config);
    CHECK(config == BorConfig{
                        .period = {
                            {0, 2},
                            {25'275'000, 5},
                            {29'638'656, 2},
                        },
                        .sprint = {
                            {0, 64},
                            {38189056, 16},
                        },
                        .jaipur_block = 123,
                    });
    CHECK(config->to_json() == json);
}

TEST_CASE("bor_config_value_lookup") {
    using namespace std::string_view_literals;
    static constexpr SmallMap<BlockNum, std::string_view> config{{20, "b"sv}, {10, "a"sv}, {30, "c"sv}};

    static_assert(!bor_config_value_lookup(config, 0));
    static_assert(!bor_config_value_lookup(config, 1));
    static_assert(!bor_config_value_lookup(config, 9));
    static_assert(*bor_config_value_lookup(config, 10) == "a"sv);
    static_assert(*bor_config_value_lookup(config, 11) == "a"sv);
    static_assert(*bor_config_value_lookup(config, 19) == "a"sv);
    static_assert(*bor_config_value_lookup(config, 20) == "b"sv);
    static_assert(*bor_config_value_lookup(config, 21) == "b"sv);
    static_assert(*bor_config_value_lookup(config, 29) == "b"sv);
    static_assert(*bor_config_value_lookup(config, 30) == "c"sv);
    static_assert(*bor_config_value_lookup(config, 31) == "c"sv);
    static_assert(*bor_config_value_lookup(config, 100) == "c"sv);
}

}  // namespace silkworm::protocol
