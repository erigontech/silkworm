/*
   Copyright 2021 The Silkworm Authors

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

#include "engine.hpp"

#include <catch2/catch.hpp>

#include <silkworm/consensus/ethash/engine.hpp>
#include <silkworm/state/in_memory_state.hpp>

namespace silkworm::consensus {

TEST_CASE("Proof-of-Stake consensus engine") {
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
    header.mix_hash = 0x2f73f29450aad18c0956ec6350524c2910f3be67ec6e80b7b597240a195788e1_bytes32;
    header.nonce = {};

    Block parent;
    parent.header.number = header.number - 1;
    parent.header.gas_limit = header.gas_limit;
    parent.header.base_fee_per_gas = 1'000'000'000;

    EthashEngine ethash_engine{kMainnetConfig};
    ProofOfStakeEngine pos_engine{kMainnetConfig};

    header.base_fee_per_gas = pos_engine.expected_base_fee_per_gas(header, parent.header);

    InMemoryState state;
    state.insert_block(parent, header.parent_hash);

    CHECK(ethash_engine.validate_block_header(header, state, /*with_future_timestamp_check=*/false) ==
          ValidationResult::kWrongDifficulty);

    CHECK(pos_engine.validate_block_header(header, state, /*with_future_timestamp_check=*/false) ==
          ValidationResult::kOk);

    header.nonce[2] = 5;
    CHECK(pos_engine.validate_block_header(header, state, /*with_future_timestamp_check=*/false) ==
          ValidationResult::kInvalidNonce);
}

}  // namespace silkworm::consensus
