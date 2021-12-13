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

#include <silkworm/common/as_range.hpp>
#include <silkworm/common/assert.hpp>
#include <silkworm/common/endian.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/etl/collector.hpp>

#include "stagedsync.hpp"

namespace silkworm::stagedsync {

StageResult BlockHashes::forward(db::RWTxn& txn) {
    /*
     * Creates HeaderNumber index by transforming
     *      from CanonicalHashes bucket : BlockNumber ->  HeaderHash
     *        to HeaderNumber bucket    : HeaderHash  ->  BlockNumber
     */

    etl::Collector collector(node_settings_->data_directory->etl().path(), node_settings_->etl_buffer_size);
    uint32_t block_number{0};
    uint32_t blocks_processed_count{0};
    auto previous_progress{db::stages::read_stage_progress(*txn, stage_name_)};
    // Corner case. If previous_progress==0 it means we have never executed this stage before
    // Otherwise we have already reached block x and we need to start from x+1
    auto expected_block_number{previous_progress ? previous_progress + 1 : previous_progress};

    auto source{db::open_cursor(*txn, db::table::kCanonicalHashes)};

    log::Trace() << stage_name_ << " started from " << expected_block_number;

    auto header_key{db::block_key(expected_block_number)};
    auto header_data{source.lower_bound(db::to_slice(header_key), /*throw_notfound*/ false)};
    while (header_data) {
        auto reached_block_number{endian::load_big_u64(static_cast<uint8_t*>(header_data.key.iov_base))};
        SILKWORM_ASSERT(reached_block_number == expected_block_number);
        SILKWORM_ASSERT(header_data.value.length() == kHashLength);
        collector.collect(
            etl::Entry{Bytes(static_cast<uint8_t*>(header_data.value.iov_base), header_data.value.iov_len),
                       Bytes(static_cast<uint8_t*>(header_data.key.iov_base), header_data.key.iov_len)});

        // Save last processed block_number and expect next in sequence
        ++blocks_processed_count;
        block_number = expected_block_number++;
        header_data = source.to_next(/*throw_notfound*/ false);
    }
    source.close();

    log::Trace() << stage_name_ << " entries collected " << blocks_processed_count;

    // Proceed only if we've done something
    if (blocks_processed_count) {
        log::Trace() << stage_name_ << " ETL load : " << human_size(collector.size());
        auto target{db::open_cursor(*txn, db::table::kHeaderNumbers)};
        auto target_rcount{txn->get_map_stat(target.map()).ms_entries};
        MDBX_put_flags_t db_flags{target_rcount ? MDBX_put_flags_t::MDBX_UPSERT : MDBX_put_flags_t::MDBX_APPEND};

        // Eventually load collected items with no transform (may throw)
        collector.load(target, nullptr, db_flags, /* log_every_percent = */ 10);

        // Update progress height with last processed block
        db::stages::write_stage_progress(*txn, db::stages::kBlockHashesKey, block_number);

        txn.commit();
    }

    log::Trace() << stage_name_ << " completed";
    return StageResult::kSuccess;
}

StageResult BlockHashes::unwind(db::RWTxn& txn, BlockNum to) {
    /*
     * Unwinds HeaderNumber index by
     *      select CanonicalHashes->HeaderHash
     *        from CanonicalHashes
     *       where CanonicalHashes->BlockNumber > to
     *        into vector;
     *    for-each vector
     *      delete HeaderNumber
     *       where HeaderNumber->HeaderHash == vector.item
     */

    auto source{db::open_cursor(*txn, db::table::kCanonicalHashes)};
    auto initial_key{db::block_key(to + 1)};
    auto source_data{source.lower_bound(db::to_slice(initial_key), false)};

    std::vector<Bytes> collected_keys;
    if (source_data) {
        db::cursor_for_each(
            source, [&collected_keys](::mdbx::cursor&, ::mdbx::cursor::move_result& _data) -> bool {
                collected_keys.emplace_back(static_cast<uint8_t*>(_data.value.iov_base), _data.value.iov_len);
                return true;
            });
    }
    source.close();

    if (!collected_keys.empty()) {
        std::sort(collected_keys.begin(), collected_keys.end());
        auto target{db::open_cursor(*txn, db::table::kHeaderNumbers)};
        as_range::for_each(collected_keys,
                           [&target](const Bytes& key) -> void { (void)target.erase(db::to_slice(key)); });
        target.close();
    }

    // Update unwind progress
    // TODO(Andrea) This might be unneeded as unwind is global within the cycle
    db::stages::write_stage_unwind(*txn, stage_name_, to);

    txn.commit();
    return StageResult::kSuccess;
}

StageResult BlockHashes::prune(db::RWTxn&) { return StageResult::kSuccess; }

}  // namespace silkworm::stagedsync
