/*
   Copyright 2022 The Silkworm Authors

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

#include "log_cbor.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/test_util.hpp>

namespace silkworm {

TEST_CASE("CBOR encoding of empty logs") {
    std::vector<Log> logs{};
    Bytes encoded{cbor_encode(logs)};
    CHECK(to_hex(encoded) == "80");
}

TEST_CASE("CBOR encoding of logs") {
    auto logs{test::sample_receipts().at(0).logs};
    auto encoded{cbor_encode(logs)};
    CHECK(to_hex(encoded) ==
          "828354ea674fdde714fd979de3edf0f56aa9716b898ec88043010043835444fd3ab8381cc3d"
          "14afa7c4af7fd13cdc65026e1825820000000000000000000000000000000000000000000000"
          "000000000000000dead582000000000000000000000000000000000000000000000000000000"
          "0000000abba46aabbff780043");
}

TEST_CASE("CBOR decoding of empty logs") {
    const auto kEmptyEncodedLogs{"80"};
    std::vector<Log> logs{};
    CHECK(cbor_decode(*from_hex(kEmptyEncodedLogs), logs));
}

TEST_CASE("CBOR decoding of logs") {
    const auto kEncoded{
        "828354ea674fdde714fd979de3edf0f56aa9716b898ec88043010043835444fd3ab8381cc3d"
        "14afa7c4af7fd13cdc65026e1825820000000000000000000000000000000000000000000000"
        "000000000000000dead582000000000000000000000000000000000000000000000000000000"
        "0000000abba46aabbff780043"};
    std::vector<Log> logs{};
    CHECK(cbor_decode(*from_hex(kEncoded), logs));
    CHECK(logs.size() == 2);
    if (logs.size() == 2) {
        CHECK(logs[0].address == 0xea674fdde714fd979de3edf0f56aa9716b898ec8_address);
        CHECK(logs[0].topics.empty());
        CHECK(logs[0].data == *from_hex("010043"));
        CHECK(logs[1].address == 0x44fd3ab8381cc3d14afa7c4af7fd13cdc65026e1_address);
        CHECK(logs[1].topics.size() == 2);
        if (logs[1].topics.size() == 2) {
            CHECK(logs[1].topics[0] == 0x000000000000000000000000000000000000000000000000000000000000dead_bytes32);
            CHECK(logs[1].topics[1] == 0x000000000000000000000000000000000000000000000000000000000000abba_bytes32);
        }
        CHECK(logs[1].data == *from_hex("aabbff780043"));
    }
}

}  // namespace silkworm
