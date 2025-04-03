// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "filter.hpp"

#include <sstream>

#include <catch2/catch_test_macros.hpp>

namespace silkworm::rpc {

using evmc::literals::operator""_address, evmc::literals::operator""_bytes32;

TEST_CASE("write null filter addresses to ostream", "[rpc][types][filter]") {
    std::optional<FilterAddresses> addresses{std::nullopt};
    std::ostringstream oss;
    oss << addresses;
    CHECK(oss.str() == "null");
}

TEST_CASE("write 0-sized filter addresses to ostream", "[rpc][types][filter]") {
    FilterAddresses addresses{};
    std::ostringstream oss;
    oss << addresses;
    CHECK(oss.str() == "[]");
}

TEST_CASE("write 1-sized filter addresses to ostream", "[rpc][types][filter]") {
    FilterAddresses addresses{0x6090a6e47849629b7245dfa1ca21d94cd15878ef_address};
    std::ostringstream oss;
    oss << addresses;
    CHECK(oss.str() == "[0x6090a6e47849629b7245dfa1ca21d94cd15878ef]");
}

TEST_CASE("write 2-sized filter addresses to ostream", "[rpc][types][filter]") {
    FilterAddresses addresses{
        0x6090a6e47849629b7245dfa1ca21d94cd15878ef_address,
        0x702a999710cfd011b475505335d4f437d8132fae_address};
    std::ostringstream oss;
    oss << addresses;
    CHECK(oss.str() == "[0x6090a6e47849629b7245dfa1ca21d94cd15878ef 0x702a999710cfd011b475505335d4f437d8132fae]");
}

TEST_CASE("write 0-sized filter subtopics to ostream", "[rpc][types][filter]") {
    FilterSubTopics subtopics{};
    std::ostringstream oss;
    oss << subtopics;
    CHECK(oss.str() == "[]");
}

TEST_CASE("write 1-sized filter subtopics to ostream", "[rpc][types][filter]") {
    FilterSubTopics subtopics{0x374f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126c_bytes32};
    std::ostringstream oss;
    oss << subtopics;
    CHECK(oss.str() == "[0x374f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126c]");
}

TEST_CASE("write 2-sized filter subtopics to ostream", "[rpc][types][filter]") {
    FilterSubTopics subtopics{
        0x0000000000000000000000000000000000000000000000000000000000000000_bytes32,
        0x374f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126c_bytes32};
    std::ostringstream oss;
    oss << subtopics;
    CHECK(oss.str() == R"([0x0000000000000000000000000000000000000000000000000000000000000000 0x374f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126c])");
}

TEST_CASE("write null filter topics to ostream", "[rpc][types][filter]") {
    std::optional<FilterTopics> topics{std::nullopt};
    std::ostringstream oss;
    oss << topics;
    CHECK(oss.str() == "null");
}

TEST_CASE("write 0-sized filter topics to ostream", "[rpc][types][filter]") {
    FilterTopics topics{};
    std::ostringstream oss;
    oss << topics;
    CHECK(oss.str() == "[]");
}

TEST_CASE("write 1-sized filter topics to ostream", "[rpc][types][filter]") {
    FilterTopics topics{
        {0x0000000000000000000000000000000000000000000000000000000000000000_bytes32},
        {0x374f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126c_bytes32},
    };
    std::ostringstream oss;
    oss << topics;
    CHECK(oss.str() == "[[0x0000000000000000000000000000000000000000000000000000000000000000] [0x374f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126c]]");
}

TEST_CASE("write filter to ostream", "[rpc][types][filter]") {
    Filter filter{
        "0",
        "10000000",
        FilterAddresses{0x6090a6e47849629b7245dfa1ca21d94cd15878ef_address},
        FilterTopics{
            {0x0000000000000000000000000000000000000000000000000000000000000000_bytes32},
            {0x374f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126c_bytes32},
        },
    };
    std::ostringstream oss;
    oss << filter;
    CHECK(oss.str() ==
          "from_block: 0, to_block: 10000000, addresses: "
          "[0x6090a6e47849629b7245dfa1ca21d94cd15878ef], topics: [[0x0000000000000000000000000000000000000000000000000000000000000000] "
          "[0x374f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126c]], block_hash: null");
}

TEST_CASE("LogFilterOptions", "[rpc][types][options]") {
    SECTION("default to ostream") {
        LogFilterOptions options;

        std::ostringstream oss;
        oss << options;
        CHECK(oss.str() ==
              "add_timestamp: false, logCount: 0, blockCount: 0, ignore_topics_order: false");
    }
    SECTION("option to ostream") {
        LogFilterOptions options{true};
        std::ostringstream oss;
        oss << options;
        CHECK(oss.str() ==
              "add_timestamp: true, logCount: 0, blockCount: 0, ignore_topics_order: false");
    }
}

}  // namespace silkworm::rpc
