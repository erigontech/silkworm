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

#include <chrono>
#include <set>
#include <thread>

#include "silkworm/common/log.hpp"
#include "silkworm/common/measure.hpp"
#include "silkworm/common/stopwatch.hpp"
#include "silkworm/db/stages.hpp"

namespace silkworm::stagedsync {

// HeaderPersistence has the responsibility to update headers related tables
class HeaderPersistence {
  public:
    explicit HeaderPersistence(db::RWTxn& tx, BlockNum headers_height);

    void update_tables(const BlockHeader&);

    static auto remove_headers(BlockNum unwind_point, std::optional<Hash> bad_block, db::RWTxn& tx)
        -> std::tuple<std::set<Hash>, BlockNum>;

    bool best_header_changed() const;
    BlockNum initial_height() const;
    BlockNum highest_height() const;
    Hash highest_hash() const;
    BigInt total_difficulty() const;

  private:
    static constexpr size_t kCanonicalCacheSize = 1000;

    db::RWTxn& tx_;
    Hash previous_hash_;
    Hash highest_hash_;
    BlockNum initial_in_db_{};
    BlockNum highest_in_db_{};
    BigInt local_td_;
    bool new_canonical_{false};
};

HeaderPersistence::HeaderPersistence(db::RWTxn& tx, BlockNum headers_height) : tx_(tx) {
    auto headers_hash = db::read_canonical_hash(tx, headers_height);
    if (!headers_hash) throw std::logic_error("Headers stage, canonical must be consistent, not found hash at height "
                                              + std::to_string(headers_height));

    std::optional<BigInt> headers_head_td = db::read_total_difficulty(tx, headers_height, *headers_hash);
    if (!headers_head_td) throw std::logic_error("Headers stage, not found total difficulty of canonical hash at height "
                                                 + std::to_string(headers_height));

    local_td_ = *headers_head_td;
    initial_in_db_ = headers_height;
    highest_in_db_ = headers_height;
}

bool HeaderPersistence::best_header_changed() const { return new_canonical_; }

BlockNum HeaderPersistence::initial_height() const { return initial_in_db_; }

BlockNum HeaderPersistence::highest_height() const { return highest_in_db_; }

Hash HeaderPersistence::highest_hash() const { return highest_hash_; }

BigInt HeaderPersistence::total_difficulty() const { return local_td_; }

void HeaderPersistence::update_tables(const BlockHeader& header) {
    // Admittance conditions
    auto height = header.number;
    Hash hash = header.hash();
    if (hash == previous_hash_) {
        return;  // skip duplicates
    }

    // Calculate total difficulty
    auto parent_td = db::read_total_difficulty(tx_, height - 1, header.parent_hash);
    if (!parent_td) {
        std::string error_message = "HeaderPersistence: parent's total difficulty not found with hash " +
                                    to_hex(header.parent_hash) + " and height " + std::to_string(height - 1) +
                                    " for header " + hash.to_hex();
        throw std::logic_error(error_message);  // unexpected condition
    }
    auto td = *parent_td + header.difficulty;  // calculated total difficulty of this header

    // Now we can decide whether this header will create a change in the canonical head
    if (td > local_td_) {
        new_canonical_ = true;

        // Save progress
        db::write_head_header_hash(tx_, hash);                                   // can throw exception

        highest_in_db_ = height;
        highest_hash_ = hash;

        local_td_ = td;  // this makes sure we end up choosing the chain with the max total difficulty
    }

    // Save progress
    db::write_total_difficulty(tx_, height, hash, td);

    // Save header number
    db::write_header_number(tx_, hash.bytes, header.number);
    // db::write_header(tx_, header, with_header_numbers);

    previous_hash_ = hash;
}

std::tuple<std::set<Hash>, BlockNum>
HeaderPersistence::remove_headers(BlockNum unwind_point, std::optional<Hash> bad_block, db::RWTxn& tx) {
    BlockNum headers_height = db::stages::read_stage_progress(tx, db::stages::kHeadersKey);

    // todo: the following code changed in Erigon, fix it

    std::set<Hash> bad_headers;
    bool is_bad_block = bad_block.has_value();
    for (BlockNum current_height = headers_height; current_height > unwind_point; current_height--) {
        if (is_bad_block) {
            auto current_hash = db::read_canonical_hash(tx, current_height);
            bad_headers.insert(*current_hash);
        }
        db::delete_canonical_hash(tx, current_height);  // do not throw if not found
    }

    BlockNum new_height = unwind_point;

    if (is_bad_block) {
        bad_headers.insert(*bad_block);

        auto [max_block_num, max_hash] = header_with_biggest_td(tx, &bad_headers);

        if (max_block_num == 0) {
            max_block_num = unwind_point;
            max_hash = *db::read_canonical_hash(tx, max_block_num);
        }

        db::write_head_header_hash(tx, max_hash);
        new_height = max_block_num;
    }

    return {bad_headers, new_height};
}

// HeadersStage
HeadersStage::HeadersStage(NodeSettings* ns, SyncContext* sc)
    : Stage(sc, db::stages::kHeadersKey, ns) {
    // User can specify to stop downloading process at some block
    const auto stop_at_block = stop_at_block_from_env();
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

    StopWatch timing;
    timing.start();
    log::Info(log_prefix_) << "Forward start";

    try {
        current_height_ = db::stages::read_stage_progress(tx, db::stages::kHeadersKey);
        BlockNum target_height = db::stages::read_stage_progress(tx, db::stages::kPipelineStartKey);

        HeaderPersistence header_persistence(tx, current_height_);

        // premature exit conditions
        if (header_persistence.canonical_repaired()) {
            tx.commit();
            log::Info(log_prefix_) << "End, forward skipped to complete the previous run (canonical chain updated), "
                                   << "duration=" << StopWatch::format(timing.lap_duration());
            return Stage::Result::kSuccess;
        }

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
        RepeatedMeasure<BlockNum> height_progress(header_persistence.initial_height());
        log::Info(log_prefix_) << "Updating headers from=" << height_progress.get();

        // header processing
        time_point_t last_update = system_clock::now();
        while (current_height_ < target_height && !is_stopping()) {
            current_height_++;

            // process header and ommers at current height
            auto processed = db::process_headers_at_height(tx, current_height_,  // may throw exception
                [&header_persistence](BlockHeader& header) {
                    header_persistence.save(header);
                });

            if (processed == 0) throw std::logic_error("table Headers has a hole");

            db::stages::write_stage_progress(tx, db::stages::kHeadersKey, current_height_);

            // show progress
            if (system_clock::now() - last_update > 30s) {
                last_update = system_clock::now();

                height_progress.set(header_persistence.highest_height());

                log::Debug(log_prefix_) << "Updated block headers number=" << height_progress.get()
                                        << " (+" << height_progress.delta() << "), "
                                        << height_progress.throughput() << " headers/secs";
            }
        }

        result = Stage::Result::kSuccess;

        // check unwind condition
        if (header_persistence.unwind_needed()) {
            result = Stage::Result::kWrongFork;
            sync_context_->unwind_point = header_persistence.unwind_point();
            // no need to set result.bad_block
            log::Info(log_prefix_) << "Unwind needed";
        }

        auto headers_processed = header_persistence.highest_height() - header_persistence.initial_height();
        log::Info(log_prefix_) << "Updating completed, wrote " << headers_processed << " headers,"
                               << " last=" << header_persistence.highest_height()
                               << " duration=" << StopWatch::format(timing.lap_duration());

        log::Info(log_prefix_) << "Updating canonical chain";
        header_persistence.finish();

        tx.commit();  // this will commit or not depending on the creator of txn

        // todo: do we need a sentry.set_status() here?

        log::Info(log_prefix_) << "Forward done, duration= " << StopWatch::format(timing.lap_duration());

    } catch (const std::exception& e) {
        log::Error(log_prefix_) << "Forward aborted due to exception: " << e.what();

        // tx rollback executed automatically if needed
        result = Stage::Result::kUnexpectedError;
    }

    return result;
}

auto HeadersStage::unwind(db::RWTxn& tx) -> Stage::Result {
    Stage::Result result{Stage::Result::kSuccess};
    operation_ = OperationType::Unwind;

    StopWatch timing;
    timing.start();
    log::Info(log_prefix_) << "Unwind start";

    current_height_ = db::stages::read_stage_progress(tx, db::stages::kHeadersKey);
    get_log_progress();  // this is a trick to set log progress initial value, please improve

    std::optional<Hash> bad_block = sync_context_->bad_block_hash;

    if (!sync_context_->unwind_point.has_value()) {
        operation_ = OperationType::None;
        return result;
    }
    auto new_height = sync_context_->unwind_point.value();

    try {
        std::set<Hash> bad_headers;
        std::tie(bad_headers, new_height) = HeaderPersistence::remove_headers(new_height, bad_block, tx);
        // todo: do we need to save bad_headers in the state and pass old bad headers here?

        current_height_ = new_height;

        result = Stage::Result::kSuccess;
..
        //update_bad_headers(std::move(bad_headers)); // TODO(mike): move this code to the consensus (?)

        tx.commit();

        // todo: do we need a sentry.set_status() here?

        log::Info(log_prefix_) << "Unwind completed, duration= " << StopWatch::format(timing.lap_duration());

    } catch (const std::exception& e) {
        log::Error(log_prefix_) << "Unwind aborted due to exception: " << e.what();

        // tx rollback executed automatically if needed
        result = Stage::Result::kUnexpectedError;
    }

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
