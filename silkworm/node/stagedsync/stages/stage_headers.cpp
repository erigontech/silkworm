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

#include "stage_headers.hpp"

#include <set>
#include <thread>

#include <magic_enum.hpp>

#include <silkworm/db/db_utils.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/common/environment.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/common/measure.hpp>

namespace silkworm::stagedsync {

HeadersStage::HeaderDataModel::HeaderDataModel(db::RWTxn& tx, BlockNum headers_height)
    : tx_(tx), data_model_(tx), previous_height_(headers_height) {
    auto headers_hash = db::read_canonical_header_hash(tx, headers_height);
    ensure(headers_hash.has_value(),
           [&]() { return "Headers stage, inconsistent canonical table: not found hash at height " + std::to_string(headers_height); });

    std::optional<intx::uint256> headers_head_td = db::read_total_difficulty(tx, headers_height, *headers_hash);
    ensure(headers_head_td.has_value(),
           [&]() { return "Headers stage, inconsistent total-difficulty table: not found td at height " +
                          std::to_string(headers_height); });

    previous_hash_ = *headers_hash;
    previous_td_ = *headers_head_td;
}

BlockNum HeadersStage::HeaderDataModel::highest_height() const { return previous_height_; }

Hash HeadersStage::HeaderDataModel::highest_hash() const { return previous_hash_; }

intx::uint256 HeadersStage::HeaderDataModel::total_difficulty() const { return previous_td_; }

void HeadersStage::HeaderDataModel::update_tables(const BlockHeader& header) {
    auto height = header.number;
    Hash hash = header.hash();

    // Admittance conditions
    ensure_invariant(header.parent_hash == previous_hash_,
                     [&]() { return "Headers stage invariant violation: headers to process must be consecutive, at height=" +
                                    std::to_string(height) + ", prev.hash=" + previous_hash_.to_hex() + ", curr.hash=" + hash.to_hex(); });

    // Calculate total difficulty of this header
    auto td = previous_td_ + header.difficulty;

    // Save progress
    db::write_total_difficulty(tx_, height, hash, td);

    previous_hash_ = hash;
    previous_td_ = td;
    previous_height_ = height;
}

void HeadersStage::HeaderDataModel::remove_headers(BlockNum unwind_point, db::RWTxn& tx) {
    auto canonical_hash = db::read_canonical_header_hash(tx, unwind_point);
    ensure(canonical_hash.has_value(), [&]() { return "Headers stage, expected canonical hash at height " + std::to_string(unwind_point); });

    db::write_head_header_hash(tx, *canonical_hash);

    // maybe we should remove only the bad header
}

std::optional<BlockHeader> HeadersStage::HeaderDataModel::get_canonical_header(BlockNum height) const {
    return data_model_.read_canonical_header(height);
}

// HeadersStage
HeadersStage::HeadersStage(SyncContext* sync_context)
    : Stage(sync_context, db::stages::kHeadersKey) {
    // User can specify to stop downloading process at some block
    const auto stop_at_block = Environment::get_stop_at_block();
    if (stop_at_block.has_value()) {
        forced_target_block_ = stop_at_block;
        log::Info(log_prefix_) << "env var STOP_AT_BLOCK set, target block=" << forced_target_block_.value();
    }
}

Stage::Result HeadersStage::forward(db::RWTxn& tx) {
    using std::shared_ptr;
    using namespace std::chrono_literals;
    using namespace std::chrono;

    Stage::Result result = Stage::Result::kUnspecified;
    std::thread message_receiving;
    operation_ = OperationType::Forward;

    try {
        auto initial_height = current_height_ = db::stages::read_stage_progress(tx, db::stages::kHeadersKey);
        BlockNum target_height = sync_context_->target_height;

        if (forced_target_block_ && current_height_ >= *forced_target_block_) {
            tx.commit_and_renew();
            log::Info(log_prefix_) << "End, forward skipped due to 'stop-at-block', current block= "
                                   << current_height_.load() << ")";
            return Stage::Result::kSuccess;
        }
        if (current_height_ >= target_height) {
            tx.commit_and_renew();
            log::Info(log_prefix_) << "End, forward skipped, we are already at the target block (" << target_height << ")";
            return Stage::Result::kSuccess;
        }
        const BlockNum segment_width{target_height - current_height_};
        if (segment_width > db::stages::kSmallBlockSegmentWidth) {
            log::Info(log_prefix_,
                      {"op", std::string(magic_enum::enum_name<OperationType>(operation_)),
                       "from", std::to_string(current_height_),
                       "to", std::to_string(target_height),
                       "span", std::to_string(segment_width)});
        }

        HeaderDataModel header_persistence(tx, current_height_);

        get_log_progress();  // this is a trick to set log progress initial value, please improve
        RepeatedMeasure<BlockNum> height_progress(current_height_);

        // header processing
        while (current_height_ < target_height && !is_stopping()) {
            current_height_++;

            // process header and ommers at current height
            auto header = header_persistence.get_canonical_header(current_height_);
            if (!header) throw std::logic_error("table Headers has a hole");

            header_persistence.update_tables(*header);

            height_progress.set(current_height_);
        }

        db::write_head_header_hash(tx, header_persistence.highest_hash());

        db::stages::write_stage_progress(tx, db::stages::kHeadersKey, current_height_);
        result = Stage::Result::kSuccess;  // no reason to raise unwind

        auto headers_processed = current_height_ - initial_height;
        log::Trace(log_prefix_) << "Update completed wrote " << headers_processed << " headers last=" << current_height_;

        tx.commit_and_renew();

    } catch (const std::exception& e) {
        log::Error(log_prefix_) << "Forward aborted due to exception: " << e.what();
        result = Stage::Result::kUnexpectedError;
    }

    operation_ = OperationType::None;
    return result;
}

Stage::Result HeadersStage::unwind(db::RWTxn& tx) {
    current_height_ = db::stages::read_stage_progress(tx, db::stages::kHeadersKey);
    get_log_progress();  // this is a trick to set log progress initial value, please improve

    if (!sync_context_->unwind_point.has_value()) return Stage::Result::kSuccess;

    auto new_height = sync_context_->unwind_point.value();
    if (current_height_ <= new_height) return Stage::Result::kSuccess;

    operation_ = OperationType::Unwind;

    const BlockNum segment_width{current_height_ - new_height};
    if (segment_width > db::stages::kSmallBlockSegmentWidth) {
        log::Info(log_prefix_,
                  {"op", std::string(magic_enum::enum_name<OperationType>(operation_)),
                   "from", std::to_string(current_height_),
                   "to", std::to_string(new_height),
                   "span", std::to_string(segment_width)});
    }

    Stage::Result result{Stage::Result::kSuccess};

    try {
        // std::optional<Hash> bad_block = sync_context_->bad_block_hash;

        HeaderDataModel::remove_headers(new_height, tx);

        current_height_ = new_height;

        db::stages::write_stage_progress(tx, db::stages::kHeadersKey, current_height_);

        result = Stage::Result::kSuccess;

        tx.commit_and_renew();

    } catch (const std::exception& e) {
        log::Error(log_prefix_) << "Unwind aborted due to exception: " << e.what();

        // tx rollback executed automatically if needed
        result = Stage::Result::kUnexpectedError;
    }

    operation_ = OperationType::None;
    return result;
}

Stage::Result HeadersStage::prune(db::RWTxn&) {
    return Stage::Result::kSuccess;
}

std::vector<std::string> HeadersStage::get_log_progress() {  // implementation MUST be thread safe
    static RepeatedMeasure<BlockNum> height_progress{0};

    height_progress.set(current_height_);

    return {"current number", std::to_string(height_progress.get()),
            "progress", std::to_string(height_progress.delta()),
            "headers/secs", std::to_string(height_progress.throughput())};
}

}  // namespace silkworm::stagedsync
