// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "filter.hpp"

#include <catch2/catch_test_macros.hpp>
#include <evmc/evmc.hpp>

namespace silkworm::rpc {

using evmc::literals::operator""_address, evmc::literals::operator""_bytes32;

TEST_CASE("serialize empty filter", "[silkworm::json][to_json]") {
    Filter f{"0", "0", FilterAddresses{}, FilterTopics(2), ""};
    nlohmann::json j = f;
    CHECK(j == R"({"blockHash":"","fromBlock":"0","toBlock":"0","topics":[[], []]})"_json);
}

TEST_CASE("serialize filter with one address", "[silkworm::json][to_json]") {
    Filter f;
    f.addresses = {{0x007fb8417eb9ad4d958b050fc3720d5b46a2c053_address}};
    nlohmann::json j = f;
    CHECK(j == R"({"address":"0x007fb8417eb9ad4d958b050fc3720d5b46a2c053"})"_json);
}

TEST_CASE("serialize filter with fromBlock and toBlock", "[silkworm::json][to_json]") {
    Filter f{"1000", "2000", FilterAddresses{}, FilterTopics(2), ""};
    nlohmann::json j = f;
    CHECK(j == R"({"blockHash":"","fromBlock":"1000","toBlock":"2000","topics":[[], []]})"_json);
}

TEST_CASE("deserialize null filter", "[silkworm::json][from_json]") {
    auto j1 = R"({})"_json;
    auto f1 = j1.get<Filter>();
    CHECK(f1.from_block == std::nullopt);
    CHECK(f1.to_block == std::nullopt);
}

TEST_CASE("deserialize empty filter", "[silkworm::json][from_json]") {
    auto j1 = R"({"address":["",""],"blockHash":"","fromBlock":0,"toBlock":0,"topics":[["",""], ["",""]]})"_json;
    auto f1 = j1.get<Filter>();
    CHECK(f1.from_block == "0x0");
    CHECK(f1.to_block == "0x0");
}

TEST_CASE("deserialize filter with topic", "[silkworm::json][from_json]") {
    auto j = R"({
        "address": "0x6090a6e47849629b7245dfa1ca21d94cd15878ef",
        "fromBlock": "0x3d0000",
        "toBlock": "0x3d2600",
        "topics": [
            null,
            "0x374f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126c"
        ]
    })"_json;
    auto f = j.get<Filter>();
    CHECK(f.from_block == "0x3d0000");
    CHECK(f.to_block == "0x3d2600");
    CHECK(f.addresses == std::vector<evmc::address>{0x6090a6e47849629b7245dfa1ca21d94cd15878ef_address});
    CHECK(f.topics == std::vector<std::vector<evmc::bytes32>>{
                          {},
                          {0x374f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126c_bytes32}});
    CHECK(f.block_hash == std::nullopt);
}

TEST_CASE("deserialize filter with topic null", "[silkworm::json][from_json]") {
    auto j = R"({
        "address": "0x6090a6e47849629b7245dfa1ca21d94cd15878ef",
        "fromBlock": "0x3d0000",
        "toBlock": "0x3d2600",
        "topics": null
    })"_json;
    auto f = j.get<Filter>();
    CHECK(f.from_block == "0x3d0000");
    CHECK(f.to_block == "0x3d2600");
    CHECK(f.addresses == std::vector<evmc::address>{0x6090a6e47849629b7245dfa1ca21d94cd15878ef_address});
    CHECK(f.block_hash == std::nullopt);
}

TEST_CASE("deserialize LogFilterOptions", "[silkworm::json][from_json]") {
    SECTION("default values") {
        auto j = R"({
            "logCount": 0,
            "blockCount": 0,
            "ignoreTopicsOrder": false
        })"_json;
        auto options = j.get<LogFilterOptions>();

        CHECK(options.log_count == 0);
        CHECK(options.block_count == 0);
        CHECK(options.ignore_topics_order == false);
    }
    SECTION("log_count != 0") {
        auto j = R"({
            "logCount": 100,
            "blockCount": 0,
            "ignoreTopicsOrder": false
        })"_json;
        auto options = j.get<LogFilterOptions>();

        CHECK(options.log_count == 100);
        CHECK(options.block_count == 0);
        CHECK(options.ignore_topics_order == false);
    }
    SECTION("block_count != 0") {
        auto j = R"({
            "logCount": 0,
            "blockCount": 100,
            "ignoreTopicsOrder": false
        })"_json;
        auto options = j.get<LogFilterOptions>();

        CHECK(options.log_count == 0);
        CHECK(options.block_count == 100);
        CHECK(options.ignore_topics_order == false);
    }
    SECTION("ignore_topics_order == true") {
        auto j = R"({
            "logCount": 0,
            "blockCount": 0,
            "ignoreTopicsOrder": true
        })"_json;
        auto options = j.get<LogFilterOptions>();

        CHECK(options.log_count == 0);
        CHECK(options.block_count == 0);
        CHECK(options.ignore_topics_order == true);
    }
}

}  // namespace silkworm::rpc
