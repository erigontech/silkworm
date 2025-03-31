// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "config.hpp"

#include <string_view>

#include <catch2/catch_test_macros.hpp>

using namespace std::string_view_literals;

namespace silkworm::protocol::bor {

using namespace evmc::literals;

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
            "validatorContract": "0x0000000000000000000000000000000000001000",
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
            "jaipurBlock": 123,
            "agraBlock": 789
        })");

    const std::optional<Config> config{Config::from_json(json)};
    REQUIRE(config);

    static constexpr Config kExpectedConfig{
        .period = {
            {0, 2},
            {25'275'000, 5},
            {29'638'656, 2},
        },
        .sprint = {
            {0, 64},
            {38189056, 16},
        },
        .validator_contract = 0x0000000000000000000000000000000000001000_address,
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
        .agra_block = 789,
    };

    CHECK(config == kExpectedConfig);
    CHECK(config->to_json() == json);
}

TEST_CASE("bor_config_value_lookup") {
    static constexpr SmallMap<BlockNum, std::string_view> kConfig{{20, "b"sv}, {10, "a"sv}, {30, "c"sv}};

    static_assert(!config_value_lookup(kConfig, 0));
    static_assert(!config_value_lookup(kConfig, 1));
    static_assert(!config_value_lookup(kConfig, 9));
    static_assert(*config_value_lookup(kConfig, 10) == "a"sv);
    static_assert(*config_value_lookup(kConfig, 11) == "a"sv);
    static_assert(*config_value_lookup(kConfig, 19) == "a"sv);
    static_assert(*config_value_lookup(kConfig, 20) == "b"sv);
    static_assert(*config_value_lookup(kConfig, 21) == "b"sv);
    static_assert(*config_value_lookup(kConfig, 29) == "b"sv);
    static_assert(*config_value_lookup(kConfig, 30) == "c"sv);
    static_assert(*config_value_lookup(kConfig, 31) == "c"sv);
    static_assert(*config_value_lookup(kConfig, 100) == "c"sv);
}

}  // namespace silkworm::protocol::bor
