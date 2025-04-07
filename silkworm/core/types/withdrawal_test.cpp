// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "withdrawal.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/trie/vector_root.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>

namespace silkworm {

using namespace evmc::literals;

TEST_CASE("Withdrawals hash") {
    std::vector<Withdrawal> withdrawals{
        {
            .index = 0,
            .validator_index = 0,
            .address = 0x6295ee1b4f6dd65047762f924ecd367c17eabf8f_address,
            .amount = 1,
        }};

    static constexpr auto kEncoder = [](Bytes& to, const Withdrawal& w) { rlp::encode(to, w); };
    CHECK(to_hex(trie::root_hash(withdrawals, kEncoder)) == "82cc6fbe74c41496b382fcdf25216c5af7bdbb5a3929e8f2e61bd6445ab66436");
}

}  // namespace silkworm
