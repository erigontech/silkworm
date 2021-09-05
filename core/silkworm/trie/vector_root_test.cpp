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

#include "vector_root.hpp"

#include <catch2/catch.hpp>

#include <silkworm/common/util.hpp>
#include <silkworm/types/receipt.hpp>
#include <silkworm/types/transaction.hpp>

namespace silkworm::trie {

TEST_CASE("Empty root hash") {
    static constexpr auto kEncoder = [](Bytes& to, const Transaction& txn) {
        rlp::encode(to, txn, /*for_signing=*/false, /*wrap_eip2718_into_array=*/false);
    };
    CHECK(root_hash(std::vector<Transaction>{}, kEncoder) == kEmptyRoot);
}

TEST_CASE("Hardcoded root hash") {
    std::vector<Receipt> receipts{
        {Transaction::Type::kLegacy, true, 21'000, {}, {}},
        {Transaction::Type::kLegacy, true, 42'000, {}, {}},
        {Transaction::Type::kLegacy,
         true,
         65'092,
         {},
         {Log{0x8d12a197cb00d4747a1fe03395095ce2a5cc6819_address,
              {0xf341246adaac6f497bc2a656f546ab9e182111d630394f0c57c710a59a2cb567_bytes32},
              *from_hex("0x000000000000000000000000000000000000000000000000000000000000000000000000000"
                        "000000000000043b2126e7a22e0c288dfb469e3de4d2c097f3ca0000000000000000000000000"
                        "000000000000000000000001195387bce41fd4990000000000000000000000000000000000000"
                        "000000000000000000000000000")}}},
    };
    for (auto& r : receipts) {
        r.bloom = logs_bloom(r.logs);
    }
    static constexpr auto kEncoder = [](Bytes& to, const Receipt& r) { rlp::encode(to, r); };
    CHECK(to_hex(root_hash(receipts, kEncoder)) == "7ea023138ee7d80db04eeec9cf436dc35806b00cc5fe8e5f611fb7cf1b35b177");
}

}  // namespace silkworm::trie
