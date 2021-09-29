/*
   Copyright 2020-2021 The Silkworm Authors

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
#include <catch2/catch.hpp>

#include "log_cbor.hpp"

#include <silkworm/common/test_util.hpp>

namespace silkworm {

TEST_CASE("CBOR encoding of empty logs") {
    std::vector<Log> logs{};
    Bytes encoded{cbor_encode(logs)};
    CHECK(to_hex(encoded) == "80");
}

TEST_CASE("CBOR encoding of logs") {
    auto logs{test::sample_receipts().at(0).logs};
    auto encoded{cbor_encode(logs)};
    CHECK(to_hex(encoded) == "828354ea674fdde714fd979de3edf0f56aa9716b898ec88043010043835444fd3ab8381cc3d"
                             "14afa7c4af7fd13cdc65026e1825820000000000000000000000000000000000000000000000"
                             "000000000000000dead582000000000000000000000000000000000000000000000000000000"
                             "0000000abba46aabbff780043");
}

}  // namespace silkworm
