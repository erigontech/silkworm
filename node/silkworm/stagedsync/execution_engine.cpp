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

namespace silkworm::stagedsync {

ExecutionEngine::ExecutionEngine(NodeSettings& ns, const db::RWAccess& dba)
    : node_settings_{ns},
      db_access_{dba},
      tx_{db_access_.start_rw_tx()},
      pipeline_{&ns},
      canonical_cache_{kCacheSize}
      //header_cache_{kCacheSize}
{
}

void ExecutionEngine::insert_headers(std::vector<std::shared_ptr<BlockHeader>>& headers) {
    SILK_TRACE << "ExecutionEngine: inserting " << headers.size() << " headers";
    if (headers.empty()) return;

    as_range::for_each(headers, [&, this](const auto& header) { insert_header(tx_, *header); });
}

void ExecutionEngine::insert_header(db::RWTxn& tx, BlockHeader& header) {
    // if (!db::has_header(tx_, header.number, header.hash())) { todo: hash() is computationally expensive
    db::write_header(tx, header, true); // todo: move?
    //}

    //header_cache_.put(header.hash(), header);
}

void ExecutionEngine::insert_bodies(std::vector<std::shared_ptr<Block>>& bodies) {
    SILK_TRACE << "ExecutionEngine: inserting " << bodies.size() << " bodies";
    if (bodies.empty()) return;

    as_range::for_each(bodies, [&, this](const auto& body) { insert_body(tx_, *body); });
}

void ExecutionEngine::insert_body(db::RWTxn& tx, Block& block) {
    Hash block_hash = block.header.hash();  // todo: hash() is computationally expensive
    BlockNum block_num = block.header.number;

    if (!db::has_body(tx, block_num, block_hash)) {
        db::write_body(tx, block, block_hash, block_num);
    }
}

auto ExecutionEngine::verify_chain(Hash header_hash) -> VerificationResult {
    // commit policy
    bool cycle_in_one_tx = !is_first_sync;
    std::unique_ptr<db::RWTxn> inner_tx{nullptr};
    if (cycle_in_one_tx)
        inner_tx = std::make_unique<db::RWTxn>(*tx_); // will defer commit to the tx
    else
        inner_tx = std::make_unique<db::RWTxn>(*db_access_);

    // forward
    Stage::Result forward_result = pipeline_.forward(*inner_tx, header_hash);

    // finish
    tx_.commit_and_renew(); // todo(mike): commit to a shard!

    switch (forward_result) {
        case Stage::Result::kSuccess:
            return ValidChain{pipeline_.head_header_number()};
        case Stage::Result::kWrongFork:
        case Stage::Result::kInvalidBlock:
        case Stage::Result::kWrongStateRoot:
            return InvalidChain{pipeline_.unwind_point().value(), pipeline_.unwind_head(), pipeline_.bad_block()};
        case Stage::Result::kStoppedByEnv:
            return ValidationError{pipeline_.head_header_number()}; // todo(mike): is it ok?
        default:
            ; // ignore?
    }

    throw StageError(forward_result);
}

bool ExecutionEngine::update_fork_choice(Hash header_hash) {
    // commit policy
    bool cycle_in_one_tx = !is_first_sync;
    std::unique_ptr<db::RWTxn> inner_tx{nullptr};
    if (cycle_in_one_tx)
        inner_tx = std::make_unique<db::RWTxn>(*tx_); // will defer commit to the tx
    else
        inner_tx = std::make_unique<db::RWTxn>(*db_access_);

    if (pipeline_.head_header_hash() != header_hash) { // todo(mike): it true in the PoW, not in the PoS
        // find forking point on canonical
        BlockNum forking_point = find_forking_point(*inner_tx, header_hash);

        // run unwind
        const auto unwind_result = pipeline_.unwind(*inner_tx, forking_point); // todo(mike): this will unwind to the unwind_point

        success_or_throw(unwind_result);  // Must be successful: no recovery from bad unwinding
    }

    // todo(mike): percorrere a ritroso la canonical e inserire gli header in cache: canonical_cache_.put(header.number, header.hash());

    is_first_sync = false;

    // finish
    tx_.commit_and_renew(); // todo: commit to a shard!

    return true;
}

BlockNum ExecutionEngine::find_forking_point(db::RWTxn& tx, Hash header_hash) {
    BlockNum forking_point{};

    std::optional<BlockHeader> header = db::read_header(tx, header_hash);
    if (!header) throw std::logic_error("find_forking_point precondition violation, header not found");

    BlockNum height = header->number;
    Hash parent_hash = header->parent_hash;

    // Read canonical hash at height-1
    auto prev_canon_hash = canonical_cache_.get_as_copy(height - 1);  // look in the cache first
    if (!prev_canon_hash) {
        prev_canon_hash = db::read_canonical_hash(tx, height - 1);  // then look in the db
    }

    // Most common case: forking point is the height of the parent header
    if (prev_canon_hash == header->parent_hash) {
        forking_point = height - 1;
    }
    // Going further back
    else {
        auto parent = db::read_header(tx, height - 1, parent_hash);
        if (!parent) {
            std::string error_message = "HeaderPersistence: could not find parent with hash " + to_hex(parent_hash) +
                                        " and height " + std::to_string(height - 1) + " for header " + to_hex(header->hash());
            log::Error("HeaderStage") << error_message;
            throw std::logic_error(error_message);
        }

        auto ancestor_hash = parent->parent_hash;
        auto ancestor_height = height - 2;

        // look in the cache first
        const Hash* cached_canon_hash;
        while ((cached_canon_hash = canonical_cache_.get(ancestor_height)) && *cached_canon_hash != ancestor_hash) {
            auto ancestor = db::read_header(tx, ancestor_height, ancestor_hash); // todo(mike): maybe use cache?
            ancestor_hash = ancestor->parent_hash;
            --ancestor_height;
        }  // if this loop finds a prev_canon_hash the next loop will be executed, is this right?

        // now look in the db
        std::optional<Hash> db_canon_hash;
        while ((db_canon_hash = read_canonical_hash(tx, ancestor_height)) && db_canon_hash != ancestor_hash) {
            auto ancestor = db::read_header(tx, ancestor_height, ancestor_hash); // todo(mike): maybe use cache?
            ancestor_hash = ancestor->parent_hash;
            --ancestor_height;
        }

        // loop above terminates when prev_canon_hash == ancestor_hash, therefore ancestor_height is our forking point
        forking_point = ancestor_height;
    }

    return forking_point;
}

auto ExecutionEngine::get_header(Hash header_hash) -> std::optional<BlockHeader> {
    //const BlockHeader* cached = header_cache_.get(header_hash);
    //if (cached) {
    //    return *cached;
    //}
    std::optional<BlockHeader> header = db::read_header(tx_, header_hash);
    return header;
}

auto ExecutionEngine::get_header(BlockNum header_heigth, Hash header_hash) -> std::optional<BlockHeader> {
    //const BlockHeader* cached = header_cache_.get(header_hash);
    //if (cached) {
    //    return *cached;
    //}
    std::optional<BlockHeader> header = db::read_header(tx_, header_heigth, header_hash);
    return header;
}

auto ExecutionEngine::get_canonical_hash(BlockNum height) -> std::optional<Hash> {
    auto hash = db::read_canonical_hash(tx_, height);
    return hash;
}

auto ExecutionEngine::get_header_td(BlockNum header_heigth, Hash header_hash) -> std::optional<BigInt> {
    return db::read_total_difficulty(tx_, header_heigth, header_hash);
}

auto ExecutionEngine::get_body(Hash header_hash) -> std::optional<BlockBody> {
    BlockBody body;
    bool found = read_body(tx_, header_hash, body);
    if (!found) return {};
    return body;
}

auto ExecutionEngine::get_headers_head() -> std::tuple<BlockNum, Hash, BigInt> {
    auto headers_head_height = db::stages::read_stage_progress(tx_, db::stages::kHeadersKey);

    auto headers_head_hash = db::read_canonical_hash(tx_, headers_head_height);
    if (!headers_head_hash) {
        throw std::logic_error("Execution, invariant violation, headers stage height not present on canonical, "
                               "height=" + std::to_string(headers_head_height));
    }

    std::optional<BigInt> headers_head_td = db::read_total_difficulty(tx_, headers_head_height, *headers_head_hash);
    if (!headers_head_td) {
        throw std::logic_error("Execution, invariant violation, total difficulty of canonical hash at height " +
                               std::to_string(headers_head_height) + " not found in db");
    }

    return {headers_head_height, *headers_head_hash, *headers_head_td}; // add headers_head_td
}

auto ExecutionEngine::get_bodies_head() -> std::tuple<BlockNum, Hash> {
    auto bodies_head_height = db::stages::read_stage_progress(tx_, db::stages::kBlockBodiesKey);
    auto bodies_head_hash = db::read_canonical_hash(tx_, bodies_head_height);
    if (!bodies_head_hash) {
        throw std::logic_error("Execution, invariant violation, body must have canonical header at same height (" +
                               std::to_string(bodies_head_height) + ")");
    }
    return {bodies_head_height, *bodies_head_hash};
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
