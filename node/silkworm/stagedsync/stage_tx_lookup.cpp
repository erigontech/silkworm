/*
   Copyright 2021-2022 The Silkworm Authors

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

#include <filesystem>

#include <silkworm/common/assert.hpp>
#include <silkworm/common/endian.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/etl/collector.hpp>

#include "stagedsync.hpp"

namespace silkworm::stagedsync {

namespace fs = std::filesystem;

StageResult stage_tx_lookup(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t prune_from) {
    fs::create_directories(etl_path);
    etl::Collector collector(etl_path, /* flush size */ 512_Mebi);

    auto expected_block_number{db::stages::read_stage_progress(*txn, db::stages::kTxLookupKey) + 1};

    // We take number from bodies table, and hash from transaction table
    auto bodies_table{db::open_cursor(*txn, db::table::kBlockBodies)};
    auto transactions_table{db::open_cursor(*txn, db::table::kBlockTransactions)};

    if (expected_block_number < prune_from) {
        expected_block_number = prune_from;
    }

    Bytes start(8, '\0');
    endian::store_big_u64(&start[0], expected_block_number);

    log::Info() << "Started Tx Lookup Extraction";

    auto bodies_data{bodies_table.lower_bound(db::to_slice(start), /*throw_notfound*/ false)};

    BlockNum block_number{0};

    while (bodies_data) {
        auto body_rlp{db::from_slice(bodies_data.value)};
        auto body{db::detail::decode_stored_block_body(body_rlp)};
        // Block number is computed here in order to record accurate stage progress
        block_number = endian::load_big_u64(static_cast<uint8_t*>(bodies_data.key.data()));
        // Iterate over transactions in current block
        if (body.txn_count) {
            // Extract compact form of big endian block number
            auto block_compact_view{zeroless_view(db::from_slice(bodies_data.key).substr(0, sizeof(BlockNum)))};
            Bytes block_compact_data{block_compact_view.data(), block_compact_view.length()};

            // Prepare to read transactions for current block
            Bytes tx_base_id(8, '\0');
            endian::store_big_u64(tx_base_id.data(), body.base_txn_id);
            auto tx_data{transactions_table.lower_bound(db::to_slice(tx_base_id), /*throw_notfound*/ false)};
            uint64_t tx_count{0};

            while (tx_data && tx_count < body.txn_count) {
                // Hash transaction rlp
                auto tx_view{db::from_slice(tx_data.value)};
                auto hash{keccak256(tx_view)};
                // Collect hash => compacted block number mapping
                etl::Entry entry{Bytes(hash.bytes, 32), block_compact_data};
                collector.collect(entry);
                ++tx_count;
                tx_data = transactions_table.to_next(/*throw_notfound*/ false);
            }
        }

        // Save last processed block_number and expect next in sequence
        if (block_number % 100000 == 0) {
            log::Info() << "Tx Lookup Extraction Progress << " << block_number;
        }

        bodies_data = bodies_table.to_next(/*throw_notfound*/ false);
    }

    log::Info() << "Entries Collected << " << collector.size();

    // Proceed only if we've done something
    if (!collector.empty()) {
        log::Info() << "Started tx Hashes Loading";

        /*
         * If we're on first sync then we shouldn't have any records in target
         * table. For this reason we can apply MDB_APPEND to load as
         * collector (with no transform) ensures collected entries
         * are already sorted. If instead target table contains already
         * some data the only option is to load in upsert mode as we
         * cannot guarantee keys are sorted amongst different calls
         * of this stage
         */
        auto target_table{db::open_cursor(*txn, db::table::kTxLookup)};
        auto target_table_rcount{txn->get_map_stat(target_table.map()).ms_entries};
        MDBX_put_flags_t db_flags{target_table_rcount ? MDBX_put_flags_t::MDBX_UPSERT : MDBX_put_flags_t::MDBX_APPEND};

        // Eventually load collected items with no transform (may throw)
        collector.load(target_table, nullptr, db_flags);

        // Update progress height with last processed block
        db::stages::write_stage_progress(*txn, db::stages::kTxLookupKey, block_number);

        txn.commit();

    } else {
        log::Info() << "Nothing to process";
    }

    log::Info() << "All Done";

    return StageResult::kSuccess;
}

StageResult unwind_tx_lookup(db::RWTxn& txn, const std::filesystem::path&, uint64_t unwind_to) {
    if (unwind_to >= db::stages::read_stage_progress(*txn, db::stages::kTxLookupKey)) {
        return StageResult::kSuccess;
    }

    auto bodies_table{db::open_cursor(*txn, db::table::kBlockBodies)};
    auto transactions_table{db::open_cursor(*txn, db::table::kBlockTransactions)};
    auto lookup_table{db::open_cursor(*txn, db::table::kTxLookup)};

    // Extract
    Bytes start(8, '\0');
    endian::store_big_u64(&start[0], unwind_to + 1);

    log::Info() << "Started Tx Lookup Unwind, from: " << db::stages::read_stage_progress(*txn, db::stages::kTxLookupKey)
                << " to: " << unwind_to;

    auto bodies_data{bodies_table.lower_bound(db::to_slice(start), /*throw_notfound*/ false)};
    while (bodies_data) {
        auto body_rlp{db::from_slice(bodies_data.value)};
        auto body{db::detail::decode_stored_block_body(body_rlp)};

        if (body.txn_count) {
            Bytes tx_base_id(8, '\0');
            endian::store_big_u64(tx_base_id.data(), body.base_txn_id);
            auto tx_data{transactions_table.lower_bound(db::to_slice(tx_base_id), /*throw_notfound*/ false)};
            uint64_t tx_count{0};

            while (tx_data && tx_count < body.txn_count) {
                auto tx_view{db::from_slice(tx_data.value)};
                auto hash{keccak256(tx_view)};
                lookup_table.erase(db::to_slice(hash.bytes));
                ++tx_count;
                tx_data = transactions_table.to_next(/*throw_notfound*/ false);
            }
        }

        bodies_data = bodies_table.to_next(/*throw_notfound*/ false);
    }

    log::Info() << "All Done";
    db::stages::write_stage_progress(*txn, db::stages::kTxLookupKey, unwind_to);

    txn.commit();

    return StageResult::kSuccess;
}

StageResult prune_tx_lookup(db::RWTxn& txn, const std::filesystem::path&, uint64_t prune_from) {
    auto lookup_table{db::open_cursor(*txn, db::table::kTxLookup)};

    log::Info() << "Pruning Transaction Lookup from: " << prune_from;

    auto lookup_data{lookup_table.to_first(/*throw_notfound*/ false)};

    while (lookup_data) {
        // Check current lookup block number
        auto block_number_view{db::from_slice(lookup_data.value)};
        uint64_t current_block{0};
        SILKWORM_ASSERT(endian::from_big_compact(block_number_view, current_block) == DecodingResult::kOk);
        // Filter out all of the lookups with invalid block numbers
        if (current_block < prune_from) {
            lookup_table.erase(/*whole_multivalue*/ false);
        }
        lookup_data = lookup_table.to_next(/*throw_notfound*/ false);
    }

    txn.commit();

    log::Info() << "Pruning Transaction Lookup finished...";

    return StageResult::kSuccess;
}

}  // namespace silkworm::stagedsync
