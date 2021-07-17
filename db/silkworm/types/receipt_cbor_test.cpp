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

namespace silkworm {

TEST_CASE("CBOR encoding of receipts") {
    std::vector<Receipt> v{};
    Bytes encoded{cbor_encode(v)};
    CHECK(to_hex(encoded) == "f6");

    v.resize(2);

    v[0].type = Transaction::Type::kLegacy;
    v[0].success = false;
    v[0].cumulative_gas_used = 0x32f05d;
    v[0].logs = {
        Log{
            0xea674fdde714fd979de3edf0f56aa9716b898ec8_address,
            {},
            *from_hex("0x010043"),
        },
        Log{
            0x44fd3ab8381cc3d14afa7c4af7fd13cdc65026e1_address,
            {to_bytes32(*from_hex("dead")), to_bytes32(*from_hex("abba"))},
            *from_hex("0xaabbff780043"),
        },
    };

    v[1].type = Transaction::Type::kEip1559;
    v[1].success = true;
    v[1].cumulative_gas_used = 0xbeadd0;
    v[1].logs = {};

    encoded = cbor_encode(v);

    CHECK(to_hex(encoded) == "828400f6001a0032f05d8402f6011a00beadd0");
}

}  // namespace silkworm
