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
#include "execution_engine.hpp"

#include <silkworm/common/as_range.hpp>
#include <silkworm/db/access_layer.hpp>

#include "sync_pipeline.hpp"

namespace silkworm::stagedsync {

ExecutionEngine::ExecutionEngine(NodeSettings& ns, const db::RWAccess& dba)
    : node_settings_{ns},
      db_access_{dba} {
}

void ExecutionEngine::insert_headers(const std::vector<BlockHeader>& headers) {
    SILK_TRACE << "ExecutionEngine: inserting " << headers.size() << " headers";
    if (headers.empty()) return;

    db::RWTxn tx = db_access_.start_rw_tx();
    as_range::for_each(headers, [&, this](const auto& header) { insert_header(tx, header); });
    tx.commit();
}

void ExecutionEngine::insert_header(db::RWTxn& tx, const BlockHeader& header) {
    // if (!db::has_header(tx_, header.number, header.hash())) { todo: hash() is computationally expensive
    db::write_header(tx, header, true);
    //}
}

void ExecutionEngine::insert_bodies(const std::vector<Block>& bodies) {
    SILK_TRACE << "ExecutionEngine: inserting " << bodies.size() << " bodies";
    if (bodies.empty()) return;

    db::RWTxn tx = db_access_.start_rw_tx();
    as_range::for_each(bodies, [&, this](const auto& body) { insert_body(tx, body); });
    tx.commit();
}

void ExecutionEngine::insert_body(db::RWTxn& tx, const Block& block) {
    Hash block_hash = block.header.hash();  // todo: hash() is computationally expensive
    BlockNum block_num = block.header.number;

    if (!db::has_body(tx, block_num, block_hash)) {
        db::write_body(tx, block, block_hash, block_num);
    }
}

bool ExecutionEngine::verify_chain(Hash header_hash) {
    db::RWTxn tx = db_access_.start_rw_tx();

    SyncPipeline pipeline(&node_settings_);
    Stage::Result forward_result = pipeline.forward(tx, header_hash);

    tx.commit(); // todo: commit to a shard!

    bool verified = (forward_result == Stage::Result::kSuccess);
    return verified;
}

/*
 * STAGE LOOP WORKER -> verify_chain
 */

/*
void SyncLoop::work() {
    Timer log_timer(
        node_settings_->asio_context, node_settings_->sync_loop_log_interval_seconds * 1'000,
        [&]() -> bool {
            if (is_stopping()) {
                log::Info(get_log_prefix()) << "stopping ...";
                return false;
            }
            log::Info(get_log_prefix(), current_stage_->second->get_log_progress());
            return true;
        },
        true);

try {
    log::Info() << "SyncLoop started";

    // Open a temporary transaction to see if we have an uncompleted Unwind from previous
    // runs.
    {
        auto txn{chaindata_env_->start_write()};
        db::Cursor source(txn, db::table::kSyncStageProgress);
        mdbx::slice key(db::stages::kUnwindKey);
        auto data{source.find(key, false)}; // throw_notfound=false
        if (data && data.value.size() == sizeof(BlockNum)) {
            sync_context_->unwind_point = endian::load_big_u64(db::from_slice(data.value).data());
        }
    }

    sync_context_->is_first_cycle = true;
    std::unique_ptr<db::RWTxn> cycle_txn{nullptr};
    mdbx::txn_managed external_txn;

    StopWatch cycle_stop_watch;

    while (!is_stopping()) {
        cycle_stop_watch.start(true); // with_reset=true

        bool cycle_in_one_tx{!sync_context_->is_first_cycle};

        {
            auto ro_tx{chaindata_env_->start_read()};
            auto from{db::stages::read_stage_progress(ro_tx, db::stages::kFinishKey)};
            auto to{db::stages::read_stage_progress(ro_tx, db::stages::kHeadersKey)};
            if (to >= from && to - from > 4096) {
                cycle_in_one_tx = false;
            }
        }

        if (cycle_in_one_tx) {
            // A single commit at the end of the cycle
            external_txn = chaindata_env_->start_write();
            cycle_txn = std::make_unique<db::RWTxn>(external_txn);
            log::Trace("SyncLoop", {"MDBX tx", "per cycle"});
        } else {
            // Single stages will commit
            cycle_txn = std::make_unique<db::RWTxn>(*chaindata_env_);
            log::Trace("SyncLoop", {"MDBX tx", "per stage"});
        }

        // Run forward
        if (!sync_context_->unwind_point.has_value()) {
            bool should_end_loop{false};

            const auto forward_result = run_cycle_forward(*cycle_txn, log_timer);

            switch (forward_result) {
                case Stage::Result::kSuccess:
                case Stage::Result::kWrongFork:
                case Stage::Result::kInvalidBlock:
                case Stage::Result::kWrongStateRoot:
                    break;  // Do nothing. Unwind is triggered afterwards
                case Stage::Result::kStoppedByEnv:
                    should_end_loop = true;
                    break;
                default:
                    throw StageError(forward_result);
            }
            if (should_end_loop) break;
        }

        // Run unwind if required
        if (sync_context_->unwind_point.has_value()) {
            // Need to persist unwind point (in case of user stop)
            db::stages::write_stage_progress(*cycle_txn, db::stages::kUnwindKey, sync_context_->unwind_point.value());
            if (cycle_in_one_tx) {
                external_txn.commit();
                external_txn = chaindata_env_->start_write();
                cycle_txn = std::make_unique<db::RWTxn>(external_txn);
            } else {
                cycle_txn->commit(true); // renew=true
            }

            // Run unwind
            log::Warning("Unwinding", {"to", std::to_string(sync_context_->unwind_point.value())});

            const auto unwind_result = run_cycle_unwind(*cycle_txn, log_timer);

            success_or_throw(unwind_result);  // Must be successful: no recovery from bad unwinding

            // Erase unwind key from progress table
            db::Cursor progress_table(*cycle_txn, db::table::kSyncStageProgress);
            mdbx::slice key(db::stages::kUnwindKey);
            (void)progress_table.erase(key);

            // Clear context
            std::swap(sync_context_->unwind_point, sync_context_->previous_unwind_point);
            sync_context_->unwind_point.reset();
            sync_context_->bad_block_hash.reset();
        }

        // Eventually run prune (should not fail)
        success_or_throw(run_cycle_prune(*cycle_txn, log_timer));

        if (cycle_in_one_tx) {
            external_txn.commit();
        } else {
            cycle_txn->commit(true); // renew=true
        }

        cycle_txn.reset();
        sync_context_->is_first_cycle = false;

        auto [_, cycle_duration] = cycle_stop_watch.lap();
        log::Info("Cycle completed", {"elapsed", StopWatch::format(cycle_duration)});
        throttle_next_cycle(cycle_duration);
    }

} catch (const StageError& ex) {
    log::Error("SyncLoop",
               {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
} catch (const mdbx::exception& ex) {
    log::Error("SyncLoop",
               {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
} catch (const std::exception& ex) {
    log::Error("SyncLoop",
               {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
} catch (...) {
    log::Error("SyncLoop",
               {"function", std::string(__FUNCTION__), "exception", "undefined"});
}

log_timer.stop();
log::Info() << "SyncLoop terminated";
}
*/
}  // namespace silkworm::stagedsync
