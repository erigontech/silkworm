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

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/test_util.hpp>
#include <silkworm/core/types/block_body_for_storage.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/test_util/temp_chain_data.hpp>
#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/node/stagedsync/stages/stage_tx_lookup.hpp>

using namespace evmc::literals;

namespace silkworm {

stagedsync::TxLookup make_tx_lookup_stage(
    stagedsync::SyncContext* sync_context,
    const db::test_util::TempChainData& chain_data) {
    return stagedsync::TxLookup{
        sync_context,
        db::etl::CollectorSettings{chain_data.dir().etl().path(), 256_Mebi},
        chain_data.prune_mode().tx_index(),
    };
}

TEST_CASE("Stage Transaction Lookups") {
    test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};

    static constexpr evmc::bytes32 hash_0{0x3ac225168df54212a25c1c01fd35bebfea408fdac2e31ddd6f80a4bbf9a5f1cb_bytes32};
    static constexpr evmc::bytes32 hash_1{0xb5553de315e0edf504d9150af82dafa5c4667fa618ed0a6f19c69b41166c5510_bytes32};

    db::test_util::TempChainData context;
    db::RWTxn& txn{context.rw_txn()};
    txn.disable_commit();

    db::PooledCursor canonicals(txn, db::table::kCanonicalHashes);
    db::PooledCursor bodies_table(txn, db::table::kBlockBodies);
    db::PooledCursor transactions_table(txn, db::table::kBlockTransactions);

    BlockBodyForStorage block;
    auto transactions{test::sample_transactions()};
    block.base_txn_id = 1;
    block.txn_count = 1 + 2;  // + 2: 2 system txs (1 at the beginning and 1 at the end)

    // ---------------------------------------
    // Push first block
    // ---------------------------------------
    Bytes tx_rlp{};
    rlp::encode(tx_rlp, transactions[0]);
    auto tx_hash_1{keccak256(tx_rlp)};

    transactions_table.upsert(db::to_slice(db::block_key(block.base_txn_id + 1)), db::to_slice(tx_rlp));
    bodies_table.upsert(db::to_slice(db::block_key(1, hash_0.bytes)), db::to_slice(block.encode()));
    REQUIRE_NOTHROW(db::write_canonical_header_hash(txn, hash_0.bytes, 1));

    // ---------------------------------------
    // Push second block
    // ---------------------------------------
    block.base_txn_id += block.txn_count;

    rlp::encode(tx_rlp, transactions[1]);
    auto tx_hash_2{keccak256(tx_rlp)};

    transactions_table.upsert(db::to_slice(db::block_key(block.base_txn_id + 1)), db::to_slice(tx_rlp));
    bodies_table.upsert(db::to_slice(db::block_key(2, hash_1.bytes)), db::to_slice(block.encode()));
    REQUIRE_NOTHROW(db::write_canonical_header_hash(txn, hash_1.bytes, 2));

    db::stages::write_stage_progress(txn, db::stages::kBlockBodiesKey, 2);
    db::stages::write_stage_progress(txn, db::stages::kBlockHashesKey, 2);
    db::stages::write_stage_progress(txn, db::stages::kExecutionKey, 2);

    SECTION("Forward checks and unwind") {
        // Execute stage forward
        stagedsync::SyncContext sync_context{};
        stagedsync::TxLookup stage_tx_lookup = make_tx_lookup_stage(&sync_context, context);
        REQUIRE(stage_tx_lookup.forward(txn) == stagedsync::Stage::Result::kSuccess);

        db::PooledCursor lookup_table(txn, db::table::kTxLookup);
        REQUIRE(lookup_table.size() == 2);  // Must be two transactions indexed

        // Retrieve block numbers associated with hashes
        auto lookup_data{lookup_table.find(db::to_slice(tx_hash_1.bytes), false)};
        REQUIRE(lookup_data.done);
        REQUIRE(!lookup_data.value.empty());
        BlockNum lookup_data_block_num{0};
        REQUIRE(endian::from_big_compact(db::from_slice(lookup_data.value), lookup_data_block_num));
        REQUIRE(lookup_data_block_num == 1u);

        lookup_data = lookup_table.find(db::to_slice(tx_hash_2.bytes), false);
        REQUIRE(lookup_data.done);
        REQUIRE(!lookup_data.value.empty());
        REQUIRE(endian::from_big_compact(db::from_slice(lookup_data.value), lookup_data_block_num));
        REQUIRE(lookup_data_block_num == 2u);

        // Execute stage unwind to block 1
        sync_context.unwind_point.emplace(1);
        REQUIRE(stage_tx_lookup.unwind(txn) == stagedsync::Stage::Result::kSuccess);
        lookup_table.bind(txn, db::table::kTxLookup);  // Needed due to commit

        // Block 1 should be still there
        lookup_data = lookup_table.find(db::to_slice(tx_hash_1.bytes), false);
        REQUIRE(lookup_data.done);
        REQUIRE(!lookup_data.value.empty());
        REQUIRE(endian::from_big_compact(db::from_slice(lookup_data.value), lookup_data_block_num));
        REQUIRE(lookup_data_block_num == 1u);

        // Block 2 must be absent due to unwind
        REQUIRE_THROWS(lookup_table.find(db::to_slice(tx_hash_2.bytes), true));
    }

    SECTION("Prune") {
        // Prune from second block, so we delete block 1
        // Alter node settings pruning
        db::PruneDistance olderHistory, olderReceipts, olderSenders, olderTxIndex, olderCallTraces;
        db::PruneThreshold beforeHistory, beforeReceipts, beforeSenders, beforeTxIndex, beforeCallTraces;
        beforeTxIndex.emplace(2);  // Will delete any transaction before block 2
        context.set_prune_mode(
            db::parse_prune_mode("t", olderHistory, olderReceipts, olderSenders, olderTxIndex, olderCallTraces,
                                 beforeHistory, beforeReceipts, beforeSenders, beforeTxIndex, beforeCallTraces));

        REQUIRE(context.prune_mode().tx_index().enabled());
        REQUIRE(context.prune_mode().tx_index().value_from_head(2) == 1);

        // Execute stage forward
        stagedsync::SyncContext sync_context{};
        stagedsync::TxLookup stage_tx_lookup = make_tx_lookup_stage(&sync_context, context);
        REQUIRE(stage_tx_lookup.forward(txn) == stagedsync::Stage::Result::kSuccess);

        // Only leave block 2 alive
        REQUIRE(stage_tx_lookup.prune(txn) == stagedsync::Stage::Result::kSuccess);

        db::PooledCursor lookup_table(txn, db::table::kTxLookup);
        REQUIRE(lookup_table.size() == 1);

        // Block 1 should NOT be there
        auto lookup_data{lookup_table.find(db::to_slice(tx_hash_1.bytes), false)};
        REQUIRE(lookup_data.done == false);

        // Block 2 should still be there
        lookup_data = lookup_table.find(db::to_slice(tx_hash_2.bytes), false);
        REQUIRE(lookup_data.done);
        REQUIRE(!lookup_data.value.empty());
        BlockNum lookup_data_block_num{0};
        REQUIRE(endian::from_big_compact(db::from_slice(lookup_data.value), lookup_data_block_num));
        REQUIRE(lookup_data_block_num == 2u);
    }
}

}  // namespace silkworm
