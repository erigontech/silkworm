// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "vector_root.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/core/types/receipt.hpp>
#include <silkworm/core/types/transaction.hpp>

namespace silkworm::trie {

TEST_CASE("Empty root hash") {
    static constexpr auto kEncoder = [](Bytes& to, const Transaction& txn) {
        rlp::encode(to, txn, /*wrap_eip2718_into_string=*/false);
    };
    CHECK(root_hash(std::vector<Transaction>{}, kEncoder) == kEmptyRoot);
}

TEST_CASE("Hardcoded root hash") {
    std::vector<Receipt> receipts{
        {TransactionType::kLegacy, true, 21'000, {}, {}},
        {TransactionType::kLegacy, true, 42'000, {}, {}},
        {TransactionType::kLegacy,
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
