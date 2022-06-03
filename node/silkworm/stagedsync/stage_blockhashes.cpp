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

#include "stage_blockhashes.hpp"

#include <memory>

#include <silkworm/common/as_range.hpp>
#include <silkworm/common/assert.hpp>
#include <silkworm/common/endian.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/etl/collector.hpp>

namespace silkworm::stagedsync {

StageResult BlockHashes::forward(db::RWTxn& txn) {
    /*
     * Creates HeaderNumber index by transforming
     *      from CanonicalHashes bucket : BlockNumber ->  HeaderHash
     *        to HeaderNumber bucket    : HeaderHash  ->  BlockNumber
     */

    if (is_stopping()) {
        return StageResult::kAborted;
    }

    // Check stage boundaries from previous execution and previous stage execution
    auto previous_progress{db::stages::read_stage_progress(*txn, stage_name_)};
    auto headers_stage_progress{db::stages::read_stage_progress(*txn, db::stages::kHeadersKey)};
    if (previous_progress == headers_stage_progress) {
        // Nothing to process
        return StageResult::kSuccess;
    } else if (previous_progress > headers_stage_progress) {
        // Something bad had happened.
        // Maybe we need to unwind ?
        log::Error() << "Bad progress sequence. BlockHashes stage progress " << previous_progress
                     << " while Headers stage " << headers_stage_progress;
        return StageResult::kInvalidProgress;
    }

    reached_block_num_ = 0;
    auto expected_block_number{previous_progress + 1};
    uint64_t headers_count{headers_stage_progress - previous_progress};
    if (headers_count > 16) {
        log::Info("Begin " + std::string(stage_name_),
                  {"from", std::to_string(expected_block_number), "to", std::to_string(headers_stage_progress)});
    }

    collector_ =
        std::make_unique<etl::Collector>(node_settings_->data_directory->etl().path(), node_settings_->etl_buffer_size);
    auto header_key{db::block_key(expected_block_number)};
    auto source{db::open_cursor(*txn, db::table::kCanonicalHashes)};
    auto data{source.find(db::to_slice(header_key), /*throw_notfound=*/false)};
    while (data.done) {
        reached_block_num_ = endian::load_big_u64(static_cast<uint8_t*>(data.key.data()));
        SILKWORM_ASSERT(reached_block_num_ == expected_block_number);
        SILKWORM_ASSERT(data.value.length() == kHashLength);
        // TODO (Andrew) is the value, key order intentional?
        collector_->collect(etl::Entry{Bytes{db::from_slice(data.value)}, Bytes{db::from_slice(data.key)}});
        // Do we need to abort ?
        if (!(expected_block_number % 1024) && is_stopping()) {
            return StageResult::kAborted;
        }
        expected_block_number++;
        data = source.to_next(/*throw_notfound=*/false);
    }

    if (reached_block_num_ != headers_stage_progress) {
        throw std::runtime_error("Unable to read all headers. Expected height " +
                                 std::to_string(headers_stage_progress) + " got " + std::to_string(reached_block_num_));
    }

    // Proceed only if we've done something
    if (!collector_->empty()) {
        auto target{db::open_cursor(*txn, db::table::kHeaderNumbers)};
        auto target_rcount{txn->get_map_stat(target.map()).ms_entries};
        MDBX_put_flags_t db_flags{target_rcount ? MDBX_put_flags_t::MDBX_UPSERT : MDBX_put_flags_t::MDBX_APPEND};

        // Eventually load collected items with no transform (may throw)
        collector_->load(target, nullptr, db_flags);

        // Update progress height with last processed block
        db::stages::write_stage_progress(*txn, stage_name_, reached_block_num_);

        txn.commit();
    }
    collector_.reset();
    return is_stopping() ? StageResult::kAborted : StageResult::kSuccess;
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

    if (is_stopping()) {
        return StageResult::kAborted;
    }

    auto source{db::open_cursor(*txn, db::table::kCanonicalHashes)};
    auto initial_key{db::block_key(to + 1)};
    auto source_data{source.lower_bound(db::to_slice(initial_key), false)};

    std::vector<Bytes> collected_keys;
    db::WalkFunc walk_func = [&collected_keys](::mdbx::cursor&, ::mdbx::cursor::move_result& data) -> bool {
        collected_keys.emplace_back(db::from_slice(data.value));
        return true;
    };
    if (source_data) {
        db::cursor_for_each(source, walk_func);
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
    if (!is_stopping()) {
        txn.commit();
        return StageResult::kSuccess;
    }
    return StageResult::kAborted;
}

StageResult BlockHashes::prune(db::RWTxn&) { return StageResult::kSuccess; }

std::vector<std::string> BlockHashes::get_log_progress() {
    if (!is_stopping()) {
        switch (current_phase_) {
            case 1:
                return {"phase", std::to_string(current_phase_) + "/2", "block", std::to_string(reached_block_num_)};
            case 2:
                return {"phase", std::to_string(current_phase_) + "/2", "key",
                        collector_ ? collector_->get_load_key() : ""};
            default:
                break;
        }
    }
    return {};
}

}  // namespace silkworm::stagedsync
