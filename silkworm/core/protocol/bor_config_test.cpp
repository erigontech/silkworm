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

using namespace std::string_view_literals;

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
            "blockAlloc": {
                "22244000": {
                    "0x0000000000000000000000000000000000001010": {
                        "code": "0x60806040526004361061019c"
                    }
                },
                "41874000": {
                    "0x0000000000000000000000000000000000001001": {
                        "code": "0x60806040523482"
                    }
                }
            },
            "jaipurBlock": 123
        })");

    const std::optional<BorConfig> config{BorConfig::from_json(json)};
    REQUIRE(config);

    static constexpr BorConfig expected_config{
        .period = {
            {0, 2},
            {25'275'000, 5},
            {29'638'656, 2},
        },
        .sprint = {
            {0, 64},
            {38189056, 16},
        },
        .rewrite_code = {
            {
                22244000,
                {{
                    0x0000000000000000000000000000000000001010_address,
                    "\x60\x80\x60\x40\x52\x60\x04\x36\x10\x61\x01\x9c"sv,
                }},
            },
            {
                41874000,
                {{
                    0x0000000000000000000000000000000000001001_address,
                    "\x60\x80\x60\x40\x52\x34\x82"sv,
                }},
            },
        },
        .jaipur_block = 123,
    };

    CHECK(config == expected_config);
    CHECK(config->to_json() == json);
}

TEST_CASE("bor_config_value_lookup") {
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
