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

#include <thread>

#include <magic_enum.hpp>

#include <silkworm/db/db_utils.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/common/environment.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/common/measure.hpp>

namespace silkworm::stagedsync {

using namespace silkworm::db;

HeadersStage::HeaderDataModel::HeaderDataModel(
    RWTxn& tx,
    DataModel data_model,
    BlockNum headers_block_num)
    : tx_(tx),
      data_model_(data_model),
      previous_block_num_(headers_block_num) {
    auto headers_hash = read_canonical_header_hash(tx, headers_block_num);
    ensure(headers_hash.has_value(),
           [&]() { return "Headers stage, inconsistent canonical table: not found hash at block_num " + std::to_string(headers_block_num); });

    std::optional<intx::uint256> headers_head_td = read_total_difficulty(tx, headers_block_num, *headers_hash);
    ensure(headers_head_td.has_value(),
           [&]() { return "Headers stage, inconsistent total-difficulty table: not found td at block_num " +
                          std::to_string(headers_block_num); });

    previous_hash_ = *headers_hash;
    previous_td_ = *headers_head_td;
}

BlockNum HeadersStage::HeaderDataModel::max_block_num() const { return previous_block_num_; }

Hash HeadersStage::HeaderDataModel::max_hash() const { return previous_hash_; }

intx::uint256 HeadersStage::HeaderDataModel::total_difficulty() const { return previous_td_; }

void HeadersStage::HeaderDataModel::update_tables(const BlockHeader& header) {
    auto block_num = header.number;
    Hash hash = header.hash();

    // Admittance conditions
    ensure_invariant(header.parent_hash == previous_hash_,
                     [&]() { return "Headers stage invariant violation: headers to process must be consecutive, at block_num=" +
                                    std::to_string(block_num) + ", prev.hash=" + previous_hash_.to_hex() + ", curr.hash=" + hash.to_hex(); });

    // Calculate total difficulty of this header
    auto td = previous_td_ + header.difficulty;

    // Save progress
    write_total_difficulty(tx_, block_num, hash, td);

    previous_hash_ = hash;
    previous_td_ = td;
    previous_block_num_ = block_num;
}

void HeadersStage::HeaderDataModel::remove_headers(BlockNum unwind_point, RWTxn& tx) {
    auto canonical_hash = read_canonical_header_hash(tx, unwind_point);
    ensure(canonical_hash.has_value(), [&]() { return "Headers stage, expected canonical hash at block_num " + std::to_string(unwind_point); });

    write_head_header_hash(tx, *canonical_hash);

    // maybe we should remove only the bad header
}

std::optional<BlockHeader> HeadersStage::HeaderDataModel::get_canonical_header(BlockNum block_num) const {
    return data_model_.read_canonical_header(block_num);
}

// HeadersStage
HeadersStage::HeadersStage(
    SyncContext* sync_context,
    DataModelFactory data_model_factory)
    : Stage{sync_context, stages::kHeadersKey},
      data_model_factory_{std::move(data_model_factory)} {
    // User can specify to stop downloading process at some block
    const auto stop_at_block = Environment::get_stop_at_block();
    if (stop_at_block.has_value()) {
        forced_target_block_ = stop_at_block;
        SILK_DEBUG_M(log_prefix_, {"target=", std::to_string(*forced_target_block_)}) << " env var STOP_AT_BLOCK set";
    }
}

Stage::Result HeadersStage::forward(RWTxn& tx) {
    using std::shared_ptr;
    using namespace std::chrono_literals;
    using namespace std::chrono;

    Stage::Result result = Stage::Result::kUnspecified;
    std::thread message_receiving;
    operation_ = OperationType::kForward;

    try {
        auto initial_block_num = current_block_num_ = stages::read_stage_progress(tx, stages::kHeadersKey);
        BlockNum target_block_num = sync_context_->target_block_num;

        if (forced_target_block_ && current_block_num_ >= *forced_target_block_) {
            tx.commit_and_renew();
            log::Trace(log_prefix_) << "End, forward skipped due to STOP_AT_BLOCK, block=" << current_block_num_.load();
            return Stage::Result::kSuccess;
        }
        if (current_block_num_ >= target_block_num) {
            tx.commit_and_renew();
            log::Trace(log_prefix_) << "End, forward skipped, we are already at target block=" << target_block_num;
            return Stage::Result::kSuccess;
        }
        const BlockNum segment_width{target_block_num - current_block_num_};
        if (segment_width > stages::kSmallBlockSegmentWidth) {
            log::Info(log_prefix_,
                      {"op", std::string(magic_enum::enum_name<OperationType>(operation_)),
                       "from", std::to_string(current_block_num_),
                       "to", std::to_string(target_block_num),
                       "span", std::to_string(segment_width)});
        }

        HeaderDataModel header_persistence{
            tx,
            data_model_factory_(tx),
            current_block_num_,
        };

        get_log_progress();  // this is a trick to set log progress initial value, please improve
        RepeatedMeasure<BlockNum> block_num_progress(current_block_num_);

        // header processing
        while (current_block_num_ < target_block_num && !is_stopping()) {
            ++current_block_num_;

            // process header and ommers at current block_num
            auto header = header_persistence.get_canonical_header(current_block_num_);
            if (!header) throw std::logic_error("table Headers has a hole");

            header_persistence.update_tables(*header);

            block_num_progress.set(current_block_num_);
        }

        write_head_header_hash(tx, header_persistence.max_hash());

        stages::write_stage_progress(tx, stages::kHeadersKey, current_block_num_);
        result = Stage::Result::kSuccess;  // no reason to raise unwind

        auto headers_processed = current_block_num_ - initial_block_num;
        log::Trace(log_prefix_) << "Update completed wrote " << headers_processed << " headers last=" << current_block_num_;

        tx.commit_and_renew();

    } catch (const std::exception& e) {
        log::Error(log_prefix_) << "Forward aborted due to exception: " << e.what();
        result = Stage::Result::kUnexpectedError;
    }

    operation_ = OperationType::kNone;
    return result;
}

Stage::Result HeadersStage::unwind(RWTxn& tx) {
    current_block_num_ = stages::read_stage_progress(tx, stages::kHeadersKey);
    get_log_progress();  // this is a trick to set log progress initial value, please improve

    if (!sync_context_->unwind_point.has_value()) return Stage::Result::kSuccess;

    auto new_block_num = sync_context_->unwind_point.value();
    if (current_block_num_ <= new_block_num) return Stage::Result::kSuccess;

    operation_ = OperationType::kUnwind;

    const BlockNum segment_width{current_block_num_ - new_block_num};
    if (segment_width > stages::kSmallBlockSegmentWidth) {
        log::Info(log_prefix_,
                  {"op", std::string(magic_enum::enum_name<OperationType>(operation_)),
                   "from", std::to_string(current_block_num_),
                   "to", std::to_string(new_block_num),
                   "span", std::to_string(segment_width)});
    }

    Stage::Result result{Stage::Result::kSuccess};

    try {
        // std::optional<Hash> bad_block = sync_context_->bad_block_hash;

        HeaderDataModel::remove_headers(new_block_num, tx);

        current_block_num_ = new_block_num;

        stages::write_stage_progress(tx, stages::kHeadersKey, current_block_num_);

        result = Stage::Result::kSuccess;

        tx.commit_and_renew();

    } catch (const std::exception& e) {
        log::Error(log_prefix_) << "Unwind aborted due to exception: " << e.what();

        // tx rollback executed automatically if needed
        result = Stage::Result::kUnexpectedError;
    }

    operation_ = OperationType::kNone;
    return result;
}

Stage::Result HeadersStage::prune(RWTxn&) {
    return Stage::Result::kSuccess;
}

std::vector<std::string> HeadersStage::get_log_progress() {  // implementation MUST be thread safe
    static RepeatedMeasure<BlockNum> block_num_progress{0};

    block_num_progress.set(current_block_num_);

    return {"current block", std::to_string(block_num_progress.get()),
            "progress", std::to_string(block_num_progress.delta()),
            "headers/secs", std::to_string(block_num_progress.throughput())};
}

}  // namespace silkworm::stagedsync
