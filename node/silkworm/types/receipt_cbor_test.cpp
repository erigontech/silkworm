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

#include "receipt_cbor.hpp"

#include <catch2/catch.hpp>

#include <silkworm/common/util.hpp>
#include <silkworm/types/transaction.hpp>
#include <silkworm/common/test_util.hpp>

namespace silkworm {

TEST_CASE("CBOR encoding of empty receipts") {
    std::vector<Receipt> v{};
    Bytes encoded{cbor_encode(v)};
    CHECK(to_hex(encoded) == "f6");
}

TEST_CASE("CBOR encoding of receipts") {
    auto v{test::sample_receipts()};
    auto encoded{cbor_encode(v)};
    CHECK(to_hex(encoded) == "828400f6001a0032f05d8402f6011a00beadd0");
}

}  // namespace silkworm
