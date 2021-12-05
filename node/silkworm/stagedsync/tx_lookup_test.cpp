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
#include <ethash/keccak.hpp>

#include <silkworm/common/test_context.hpp>
#include <silkworm/common/test_util.hpp>

#include "stagedsync.hpp"

using namespace evmc::literals;

namespace silkworm {

TEST_CASE("Stage Transaction Lookups") {
    static constexpr evmc::bytes32 hash_0{0x3ac225168df54212a25c1c01fd35bebfea408fdac2e31ddd6f80a4bbf9a5f1cb_bytes32};
    static constexpr evmc::bytes32 hash_1{0xb5553de315e0edf504d9150af82dafa5c4667fa618ed0a6f19c69b41166c5510_bytes32};

    test::Context context;
    db::RWTxn txn{context.txn()};

    auto bodies_table{db::open_cursor(*txn, db::table::kBlockBodies)};
    auto transaction_table{db::open_cursor(*txn, db::table::kBlockTransactions)};

    db::detail::BlockBodyForStorage block{};
    auto transactions{test::sample_transactions()};
    block.base_txn_id = 1;
    block.txn_count = 1;
    // ---------------------------------------
    // Push first block
    // ---------------------------------------
    Bytes tx_rlp{};
    rlp::encode(tx_rlp, transactions[0]);
    auto tx_hash_1{keccak256(tx_rlp)};

    transaction_table.upsert(db::to_slice(db::block_key(1)), db::to_slice(tx_rlp));
    bodies_table.upsert(db::to_slice(db::block_key(1, hash_0.bytes)), db::to_slice(block.encode()));

    // ---------------------------------------
    // Push second block
    // ---------------------------------------

    block.base_txn_id = 2;

    rlp::encode(tx_rlp, transactions[1]);
    auto tx_hash_2{keccak256(tx_rlp)};

    transaction_table.upsert(db::to_slice(db::block_key(2)), db::to_slice(tx_rlp));
    bodies_table.upsert(db::to_slice(db::block_key(2, hash_1.bytes)), db::to_slice(block.encode()));

    // Execute stage forward
    REQUIRE(stagedsync::stage_tx_lookup(txn, context.dir().etl().path()) == stagedsync::StageResult::kSuccess);

    SECTION("Forward checks and unwind") {
        auto lookup_table{db::open_cursor(*txn, db::table::kTxLookup)};
        // Retrieve numbers associated with hashes
        auto got_block_0{db::from_slice(lookup_table.find(db::to_slice(tx_hash_1.bytes)).value)};
        auto got_block_1{db::from_slice(lookup_table.find(db::to_slice(tx_hash_2.bytes)).value)};
        // Keys must be compact and equivalent to block number
        CHECK(got_block_0.compare(ByteView({1})) == 0);
        CHECK(got_block_1.compare(ByteView({2})) == 0);

        // Execute stage unwind
        REQUIRE(stagedsync::unwind_tx_lookup(txn, context.dir().etl().path(), 1) == stagedsync::StageResult::kSuccess);

        lookup_table = db::open_cursor(*txn, db::table::kTxLookup);
        // Unwind block should be still there
        got_block_0 = db::from_slice(lookup_table.find(db::to_slice(tx_hash_1.bytes)).value);
        REQUIRE(got_block_0.compare(ByteView({1})) == 0);
        // Block 2 must be absent due to unwind
        CHECK(!lookup_table.seek(db::to_slice(tx_hash_2.bytes)));
    }

    SECTION("Prune") {
        // Only leave block 2 alive
        REQUIRE(stagedsync::prune_tx_lookup(txn, context.dir().etl().path(), 2) == stagedsync::StageResult::kSuccess);

        auto lookup_table{db::open_cursor(*txn, db::table::kTxLookup)};
        // Unwind block should be still there
        auto got_block_1{db::from_slice(lookup_table.find(db::to_slice(tx_hash_2.bytes)).value)};
        REQUIRE(got_block_1.compare(ByteView({2})) == 0);
        // Block 2 must be absent due to unwind
        CHECK(!lookup_table.seek(db::to_slice(tx_hash_1.bytes)));
    }
}

}  // namespace silkworm
