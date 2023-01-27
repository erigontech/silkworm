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

#include <silkworm/common/environment.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/common/measure.hpp>
#include <silkworm/common/stopwatch.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/downloader/internals/db_utils.hpp>

namespace silkworm::stagedsync {

HeadersStage::HeaderDataModel::HeaderDataModel(db::RWTxn& tx, BlockNum headers_height) : tx_(tx) {
    auto headers_hash = db::read_canonical_hash(tx, headers_height);
    if (!headers_hash) throw std::logic_error("Headers stage, canonical must be consistent, not found hash at height " + std::to_string(headers_height));

    std::optional<BigInt> headers_head_td = db::read_total_difficulty(tx, headers_height, *headers_hash);
    if (!headers_head_td) throw std::logic_error("Headers stage, not found total difficulty of canonical hash at height " + std::to_string(headers_height));

    previous_hash_ = *headers_hash;
    previous_td_ = *headers_head_td;
    previous_height_ = headers_height;
}

BlockNum HeadersStage::HeaderDataModel::highest_height() const { return previous_height_; }

Hash HeadersStage::HeaderDataModel::highest_hash() const { return previous_hash_; }

BigInt HeadersStage::HeaderDataModel::total_difficulty() const { return previous_td_; }

void HeadersStage::HeaderDataModel::update_tables(const BlockHeader& header) {
    auto height = header.number;
    Hash hash = header.hash();

    // Admittance conditions
    if (header.parent_hash != previous_hash_) {
        throw std::logic_error("HeadersStage invariant violation: headers to process must be consecutive, at height=" +
                               std::to_string(height) + ", prev.hash=" + previous_hash_.to_hex() + ", curr.hash=" + hash.to_hex());
    }

    // Calculate total difficulty of this header
    auto td = previous_td_ + header.difficulty;

    // Save progress
    db::write_total_difficulty(tx_, height, hash, td);  // maybe it should be moved to ExecEngine
                                                        // insert_headers to write td for every header
    // Save header number
    db::write_header_number(tx_, hash.bytes, header.number);  // maybe it should be moved to ExecEngine

    previous_hash_ = hash;
    previous_td_ = td;
    previous_height_ = height;
}

void HeadersStage::HeaderDataModel::remove_headers(BlockNum unwind_point, db::RWTxn& tx) {
    auto canonical_hash = db::read_canonical_hash(tx, unwind_point);
    if (!canonical_hash)
        throw std::logic_error("Headers stage, expected canonical hash at heigth " + std::to_string(unwind_point));
    db::write_head_header_hash(tx, *canonical_hash);
}

// HeadersStage
HeadersStage::HeadersStage(NodeSettings* ns, SyncContext* sc)
    : Stage(sc, db::stages::kHeadersKey, ns) {
    // User can specify to stop downloading process at some block
    const auto stop_at_block = Environment::get_stop_at_block();
    if (stop_at_block.has_value()) {
        forced_target_block_ = stop_at_block;
        log::Info(log_prefix_) << "env var STOP_AT_BLOCK set, target block=" << forced_target_block_.value();
    }
}

auto HeadersStage::forward(db::RWTxn& tx) -> Stage::Result {
    using std::shared_ptr;
    using namespace std::chrono_literals;
    using namespace std::chrono;

    Stage::Result result = Stage::Result::kUnspecified;
    std::thread message_receiving;
    operation_ = OperationType::Forward;

    try {
        auto initial_height = current_height_ = db::stages::read_stage_progress(tx, db::stages::kHeadersKey);
        BlockNum target_height = sync_context_->target_height;

        HeaderDataModel data_model(tx, current_height_);

        if (forced_target_block_ && current_height_ >= *forced_target_block_) {
            tx.commit();
            log::Info(log_prefix_) << "End, forward skipped due to 'stop-at-block', current block= "
                                   << current_height_.load() << ")";
            return Stage::Result::kSuccess;
        }

        if (current_height_ >= target_height) {
            tx.commit();
            log::Info(log_prefix_) << "End, forward skipped, we are already at the target block (" << target_height << ")";
            return Stage::Result::kSuccess;
        }

        get_log_progress();  // this is a trick to set log progress initial value, please improve
        RepeatedMeasure<BlockNum> height_progress(current_height_);
        log::Info(log_prefix_) << "Updating headers from=" << height_progress.get();

        // header processing
        while (current_height_ < target_height && !is_stopping()) {
            current_height_++;

            // process header and ommers at current height
            auto header = db::read_canonical_header(tx, current_height_);
            if (!header) throw std::logic_error("table Headers has a hole");

            data_model.update_tables(*header);

            height_progress.set(current_height_);
        }

        db::write_head_header_hash(tx, data_model.highest_hash());

        db::stages::write_stage_progress(tx, db::stages::kHeadersKey, current_height_);
        result = Stage::Result::kSuccess;  // no reason to raise unwind

        auto headers_processed = current_height_ - initial_height;
        log::Info(log_prefix_) << "Updating completed, wrote " << headers_processed << " headers,"
                               << " last=" << current_height_;

        tx.commit();  // this will commit or not depending on the creator of txn

    } catch (const std::exception& e) {
        log::Error(log_prefix_) << "Forward aborted due to exception: " << e.what();
        result = Stage::Result::kUnexpectedError;
    }

    operation_ = OperationType::None;
    return result;
}

auto HeadersStage::unwind(db::RWTxn& tx) -> Stage::Result {
    current_height_ = db::stages::read_stage_progress(tx, db::stages::kHeadersKey);
    get_log_progress();  // this is a trick to set log progress initial value, please improve

    if (!sync_context_->unwind_point.has_value()) return Stage::Result::kSuccess;

    auto new_height = sync_context_->unwind_point.value();
    if (current_height_ <= new_height) return Stage::Result::kSuccess;

    Stage::Result result{Stage::Result::kSuccess};
    operation_ = OperationType::Unwind;

    try {
        // std::optional<Hash> bad_block = sync_context_->bad_block_hash;

        HeaderDataModel::remove_headers(new_height, tx);

        current_height_ = new_height;

        db::stages::write_stage_progress(tx, db::stages::kHeadersKey, current_height_);

        result = Stage::Result::kSuccess;

        tx.commit();

    } catch (const std::exception& e) {
        log::Error(log_prefix_) << "Unwind aborted due to exception: " << e.what();

        // tx rollback executed automatically if needed
        result = Stage::Result::kUnexpectedError;
    }

    operation_ = OperationType::None;
    return result;
}

auto HeadersStage::prune(db::RWTxn&) -> Stage::Result {
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
