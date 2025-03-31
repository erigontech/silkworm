// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/test_util.hpp>
#include <silkworm/core/types/block_body_for_storage.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/test_util/temp_chain_data.hpp>
#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/node/stagedsync/stages/stage_tx_lookup.hpp>

namespace silkworm {

using namespace silkworm::db;
using namespace silkworm::datastore::kvdb;
using namespace evmc::literals;
using db::test_util::TempChainDataStore;

stagedsync::TxLookup make_tx_lookup_stage(
    stagedsync::SyncContext* sync_context,
    TempChainDataStore& chain_data) {
    return stagedsync::TxLookup{
        sync_context,
        chain_data.data_model_factory(),
        datastore::etl::CollectorSettings{chain_data.dir().temp().path(), 256_Mebi},
        chain_data.prune_mode().tx_index(),
    };
}

TEST_CASE("Stage Transaction Lookups") {
    const evmc::bytes32 hash_0{0x3ac225168df54212a25c1c01fd35bebfea408fdac2e31ddd6f80a4bbf9a5f1cb_bytes32};
    const evmc::bytes32 hash_1{0xb5553de315e0edf504d9150af82dafa5c4667fa618ed0a6f19c69b41166c5510_bytes32};

    TempChainDataStore context;
    RWTxn& txn{context.rw_txn()};
    txn.disable_commit();

    PooledCursor canonicals(txn, table::kCanonicalHashes);
    PooledCursor bodies_table(txn, table::kBlockBodies);
    PooledCursor transactions_table(txn, table::kBlockTransactions);

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

    transactions_table.upsert(to_slice(block_key(block.base_txn_id + 1)), to_slice(tx_rlp));
    bodies_table.upsert(to_slice(block_key(1, hash_0.bytes)), to_slice(block.encode()));
    REQUIRE_NOTHROW(write_canonical_header_hash(txn, hash_0.bytes, 1));

    // ---------------------------------------
    // Push second block
    // ---------------------------------------
    block.base_txn_id += block.txn_count;

    rlp::encode(tx_rlp, transactions[1]);
    auto tx_hash_2{keccak256(tx_rlp)};

    transactions_table.upsert(to_slice(block_key(block.base_txn_id + 1)), to_slice(tx_rlp));
    bodies_table.upsert(to_slice(block_key(2, hash_1.bytes)), to_slice(block.encode()));
    REQUIRE_NOTHROW(write_canonical_header_hash(txn, hash_1.bytes, 2));

    stages::write_stage_progress(txn, stages::kBlockBodiesKey, 2);
    stages::write_stage_progress(txn, stages::kBlockHashesKey, 2);
    stages::write_stage_progress(txn, stages::kExecutionKey, 2);

    SECTION("Forward checks and unwind") {
        // Execute stage forward
        stagedsync::SyncContext sync_context{};
        stagedsync::TxLookup stage_tx_lookup = make_tx_lookup_stage(&sync_context, context);
        REQUIRE(stage_tx_lookup.forward(txn) == stagedsync::Stage::Result::kSuccess);

        PooledCursor lookup_table(txn, table::kTxLookup);
        REQUIRE(lookup_table.size() == 2);  // Must be two transactions indexed

        // Retrieve block numbers associated with hashes
        auto lookup_data{lookup_table.find(to_slice(tx_hash_1.bytes), false)};
        REQUIRE(lookup_data.done);
        REQUIRE(!lookup_data.value.empty());
        BlockNum lookup_data_block_num{0};
        REQUIRE(endian::from_big_compact(from_slice(lookup_data.value), lookup_data_block_num));
        REQUIRE(lookup_data_block_num == 1u);

        lookup_data = lookup_table.find(to_slice(tx_hash_2.bytes), false);
        REQUIRE(lookup_data.done);
        REQUIRE(!lookup_data.value.empty());
        REQUIRE(endian::from_big_compact(from_slice(lookup_data.value), lookup_data_block_num));
        REQUIRE(lookup_data_block_num == 2u);

        // Execute stage unwind to block 1
        sync_context.unwind_point.emplace(1);
        REQUIRE(stage_tx_lookup.unwind(txn) == stagedsync::Stage::Result::kSuccess);
        lookup_table.bind(txn, table::kTxLookup);  // Needed due to commit

        // Block 1 should be still there
        lookup_data = lookup_table.find(to_slice(tx_hash_1.bytes), false);
        REQUIRE(lookup_data.done);
        REQUIRE(!lookup_data.value.empty());
        REQUIRE(endian::from_big_compact(from_slice(lookup_data.value), lookup_data_block_num));
        REQUIRE(lookup_data_block_num == 1u);

        // Block 2 must be absent due to unwind
        REQUIRE_THROWS(lookup_table.find(to_slice(tx_hash_2.bytes), true));
    }

    SECTION("Prune") {
        // Prune from second block, so we delete block 1
        // Alter node settings pruning
        PruneDistance older_history, older_receipts, older_senders, older_tx_index, older_call_traces;
        PruneThreshold before_history, before_receipts, before_senders, before_tx_index, before_call_traces;
        before_tx_index.emplace(2);  // Will delete any transaction before block 2
        context.set_prune_mode(
            parse_prune_mode("t", older_history, older_receipts, older_senders, older_tx_index, older_call_traces,
                             before_history, before_receipts, before_senders, before_tx_index, before_call_traces));

        REQUIRE(context.prune_mode().tx_index().enabled());
        REQUIRE(context.prune_mode().tx_index().value_from_head(2) == 1);

        // Execute stage forward
        stagedsync::SyncContext sync_context{};
        stagedsync::TxLookup stage_tx_lookup = make_tx_lookup_stage(&sync_context, context);
        REQUIRE(stage_tx_lookup.forward(txn) == stagedsync::Stage::Result::kSuccess);

        // Only leave block 2 alive
        REQUIRE(stage_tx_lookup.prune(txn) == stagedsync::Stage::Result::kSuccess);

        PooledCursor lookup_table(txn, table::kTxLookup);
        REQUIRE(lookup_table.size() == 1);

        // Block 1 should NOT be there
        auto lookup_data{lookup_table.find(to_slice(tx_hash_1.bytes), false)};
        REQUIRE(lookup_data.done == false);

        // Block 2 should still be there
        lookup_data = lookup_table.find(to_slice(tx_hash_2.bytes), false);
        REQUIRE(lookup_data.done);
        REQUIRE(!lookup_data.value.empty());
        BlockNum lookup_data_block_num{0};
        REQUIRE(endian::from_big_compact(from_slice(lookup_data.value), lookup_data_block_num));
        REQUIRE(lookup_data_block_num == 2u);
    }
}

}  // namespace silkworm
