// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "merge_rule_set.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/core/state/in_memory_state.hpp>

#include "ethash_rule_set.hpp"

namespace silkworm::protocol {

TEST_CASE("Proof-of-Stake RuleSet") {
    BlockHeader header;
    header.parent_hash = 0xfe92df9ede9d5074e5439198607f01714d6ed665f92d63df8764c1d46e65e795_bytes32;
    header.ommers_hash = kEmptyListHash;
    header.beneficiary = 0x002e08000acbbae2155fab7ac01929564949070d_address;
    header.state_root = 0x1e9e5c33cff9f79838862632235f310c4b378c69b2778b24f506a4898c6d00ef_bytes32;
    header.transactions_root = kEmptyRoot;
    header.receipts_root = kEmptyRoot;
    header.difficulty = 0;
    header.number = 14'000'000;
    header.gas_limit = 30'000'000;
    header.gas_used = 0;
    header.timestamp = 1'650'000'000;
    header.prev_randao = 0x2f73f29450aad18c0956ec6350524c2910f3be67ec6e80b7b597240a195788e1_bytes32;
    header.nonce = {};

    Block parent;
    parent.header.number = header.number - 1;
    parent.header.gas_limit = header.gas_limit;
    parent.header.base_fee_per_gas = 1'000'000'000;
    parent.header.difficulty = 1000;

    ChainConfig config{kMainnetConfig};
    config.terminal_total_difficulty = parent.header.difficulty;

    MergeRuleSet rule_set{std::make_unique<EthashRuleSet>(config), config};

    header.base_fee_per_gas = expected_base_fee_per_gas(parent.header);

    InMemoryState state;
    state.insert_block(parent, header.parent_hash);

    CHECK(rule_set.validate_block_header(header, state, /*with_future_timestamp_check=*/false) ==
          ValidationResult::kOk);

    header.nonce[2] = 5;
    CHECK(rule_set.validate_block_header(header, state, /*with_future_timestamp_check=*/false) ==
          ValidationResult::kInvalidNonce);
    header.nonce[2] = 0;

    header.difficulty = 1000;
    CHECK(rule_set.validate_block_header(header, state, /*with_future_timestamp_check=*/false) ==
          ValidationResult::kPoWBlockAfterMerge);
}

}  // namespace silkworm::protocol
