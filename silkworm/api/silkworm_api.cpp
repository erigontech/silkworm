/*
   Copyright 2023 The Silkworm Authors

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

#include "silkworm_api.h"

#include <chrono>
#include <vector>

#include <boost/circular_buffer.hpp>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/execution/execution.hpp>
#include <silkworm/core/types/call_traces.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/signal_handler.hpp>
#include <silkworm/infra/concurrency/thread_pool.hpp>
#include <silkworm/node/db/access_layer.hpp>
#include <silkworm/node/db/buffer.hpp>
#include <silkworm/node/snapshot/index.hpp>
#include <silkworm/node/snapshot/repository.hpp>

using namespace std::chrono_literals;
using namespace silkworm;

static MemoryMappedRegion make_region(const SilkwormMemoryMappedFile& mmf) {
    return {mmf.memory_address, mmf.memory_length};
}

//! Log configuration matching Erigon log format
static log::Settings kLogSettingsLikeErigon{
    .log_utc = false,
    .log_timezone = false,
    .log_nocolor = false,
    .log_trim = true,
};

//! Generate log arguments for specified block
static log::Args log_args_for_exec_progress(uint64_t current_block) {
    return {
        "number",
        std::to_string(current_block),
        // TODO(canepat) compute values
        "blk/s",
        std::to_string(0.0),
        "tx/s",
        std::to_string(0.0),
        "Mgas/s",
        std::to_string(0.0),
        "gasState",
        std::to_string(0.0),
    };
}

struct SilkwormInstance {
    SilkwormHandle* handle{nullptr};
};
SilkwormInstance instance;  // just one instance for the time being

SILKWORM_EXPORT int silkworm_init(SilkwormHandle** handle) SILKWORM_NOEXCEPT {
    if (!handle) {
        return SILKWORM_INVALID_HANDLE;
    }
    if (instance.handle) {
        return SILKWORM_TOO_MANY_INSTANCES;
    }
    log::init(kLogSettingsLikeErigon);
    const auto snapshot_repository = new snapshot::SnapshotRepository{};
    db::DataModel::set_snapshot_repository(snapshot_repository);
    *handle = reinterpret_cast<SilkwormHandle*>(snapshot_repository);
    instance.handle = *handle;
    SignalHandler::init(/*custom_handler=*/{}, /*silent=*/true);
    return SILKWORM_OK;
}

SILKWORM_EXPORT int silkworm_build_recsplit_indexes(SilkwormHandle* handle, struct SilkwormMemoryMappedFile* snapshots[], int len) SILKWORM_NOEXCEPT {
    const int kNeededIndexesToBuildInParallel = 2;

    if (!handle) {
        return SILKWORM_INVALID_HANDLE;
    }

    std::vector<std::shared_ptr<snapshot::Index>> needed_indexes;
    for (int i = 0; i < len; i++) {
        struct SilkwormMemoryMappedFile* snapshot = snapshots[i];
        if (!snapshot) {
            return SILKWORM_INVALID_SNAPSHOT;
        }
        auto snapshot_region = make_region(*snapshot);

        const auto snapshot_path = snapshot::SnapshotPath::parse(snapshot->file_path);
        if (!snapshot_path) {
            return SILKWORM_INVALID_PATH;
        }

        std::shared_ptr<snapshot::Index> index;
        switch (snapshot_path->type()) {
            case snapshot::SnapshotType::headers: {
                index = std::make_shared<snapshot::HeaderIndex>(*snapshot_path, snapshot_region);
                break;
            }
            case snapshot::SnapshotType::bodies: {
                index = std::make_shared<snapshot::BodyIndex>(*snapshot_path, snapshot_region);
                break;
            }
            case snapshot::SnapshotType::transactions: {
                index = std::make_shared<snapshot::TransactionIndex>(*snapshot_path, snapshot_region);
                break;
            }
            default: {
                SILKWORM_ASSERT(false);
            }
        }
        needed_indexes.push_back(index);
    }

    if (needed_indexes.size() < kNeededIndexesToBuildInParallel) {
        // sequential build
        for (const auto& index : needed_indexes) {
            SILK_INFO << "SnapshotSync: build index: " << index->path().filename() << " start";
            index->build();
            SILK_INFO << "SnapshotSync: build index: " << index->path().filename() << " end";
        }
    } else {
        // parallel build
        ThreadPool workers;

        // Create worker tasks for missing indexes
        for (const auto& index : needed_indexes) {
            workers.push_task([=]() {
                SILK_INFO << "SnapshotSync: build index: " << index->path().filename() << " start";
                index->build();
                SILK_INFO << "SnapshotSync: build index: " << index->path().filename() << " end";
            });
        }

        // Wait for all missing indexes to be built or stop request
        while (workers.get_tasks_total()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        // Wait for any already-started-but-unfinished work in case of stop request
        workers.pause();
        workers.wait_for_tasks();
    }

    return SILKWORM_OK;
}

SILKWORM_EXPORT int silkworm_add_snapshot(SilkwormHandle* handle, SilkwormChainSnapshot* snapshot) SILKWORM_NOEXCEPT {
    if (!handle) {
        return SILKWORM_INVALID_HANDLE;
    }
    if (!snapshot) {
        return SILKWORM_INVALID_SNAPSHOT;
    }
    const auto snapshot_repository = reinterpret_cast<snapshot::SnapshotRepository*>(handle);

    const SilkwormHeadersSnapshot& hs = snapshot->headers;
    const auto headers_segment_path = snapshot::SnapshotPath::parse(hs.segment.file_path);
    if (!headers_segment_path) {
        return SILKWORM_INVALID_PATH;
    }
    snapshot::MappedHeadersSnapshot mapped_h_snapshot{
        .segment = make_region(hs.segment),
        .header_hash_index = make_region(hs.header_hash_index)};
    auto headers_snapshot = std::make_unique<snapshot::HeaderSnapshot>(*headers_segment_path, mapped_h_snapshot);
    headers_snapshot->reopen_segment();
    headers_snapshot->reopen_index();

    const SilkwormBodiesSnapshot& bs = snapshot->bodies;
    const auto bodies_segment_path = snapshot::SnapshotPath::parse(bs.segment.file_path);
    if (!bodies_segment_path) {
        return SILKWORM_INVALID_PATH;
    }
    snapshot::MappedBodiesSnapshot mapped_b_snapshot{
        .segment = make_region(bs.segment),
        .block_num_index = make_region(bs.block_num_index)};
    auto bodies_snapshot = std::make_unique<snapshot::BodySnapshot>(*bodies_segment_path, mapped_b_snapshot);
    bodies_snapshot->reopen_segment();
    bodies_snapshot->reopen_index();

    const SilkwormTransactionsSnapshot& ts = snapshot->transactions;
    const auto transactions_segment_path = snapshot::SnapshotPath::parse(ts.segment.file_path);
    if (!transactions_segment_path) {
        return SILKWORM_INVALID_PATH;
    }
    snapshot::MappedTransactionsSnapshot mapped_t_snapshot{
        .segment = make_region(ts.segment),
        .tx_hash_index = make_region(ts.tx_hash_index),
        .tx_hash_2_block_index = make_region(ts.tx_hash_2_block_index)};
    auto transactions_snapshot = std::make_unique<snapshot::TransactionSnapshot>(*transactions_segment_path, mapped_t_snapshot);
    transactions_snapshot->reopen_segment();
    transactions_snapshot->reopen_index();

    snapshot::SnapshotBundle bundle{
        .headers_snapshot_path = *headers_segment_path,
        .headers_snapshot = std::move(headers_snapshot),
        .bodies_snapshot_path = *bodies_segment_path,
        .bodies_snapshot = std::move(bodies_snapshot),
        .tx_snapshot_path = *transactions_segment_path,
        .tx_snapshot = std::move(transactions_snapshot)};
    snapshot_repository->add_snapshot_bundle(std::move(bundle));
    return SILKWORM_OK;
}

SILKWORM_EXPORT
int silkworm_execute_blocks(SilkwormHandle* handle, MDBX_txn* mdbx_txn, uint64_t chain_id, uint64_t start_block, uint64_t max_block,
                            uint64_t batch_size, bool write_change_sets, bool write_receipts, bool write_call_traces,
                            uint64_t* last_executed_block, int* mdbx_error_code) SILKWORM_NOEXCEPT {
    if (!handle) {
        return SILKWORM_INVALID_HANDLE;
    }
    if (!mdbx_txn) {
        return SILKWORM_INVALID_MDBX_TXN;
    }
    if (start_block > max_block) {
        return SILKWORM_INVALID_BLOCK_RANGE;
    }
    const auto chain_info = lookup_known_chain(chain_id);
    if (!chain_info) {
        return SILKWORM_UNKNOWN_CHAIN_ID;
    }
    const ChainConfig* chain_config{chain_info->second};

    try {
        // Wrap MDBX txn into an internal *unmanaged* txn, i.e. MDBX txn is only used but neither aborted nor committed
        db::RWTxnUnmanaged txn{mdbx_txn};

        db::Buffer state_buffer{txn, /*prune_history_threshold=*/0};
        db::DataModel access_layer{txn};

        static constexpr size_t kCacheSize{5'000};
        AnalysisCache analysis_cache{kCacheSize};
        ObjectPool<evmone::ExecutionState> state_pool;

        // Transform batch size limit into gas units (Ggas = Giga gas, Tgas = Tera gas)
        const size_t gas_max_history_size{batch_size * 1_Kibi / 2};  // 512MB -> 256Ggas roughly
        const size_t gas_max_batch_size{gas_max_history_size * 20};  // 256Ggas -> 5Tgas roughly

        // Preload requested blocks in batches from storage, i.e. from MDBX database or snapshots
        static constexpr size_t kMaxPrefetchedBlocks{10240};
        boost::circular_buffer<Block> prefetched_blocks{/*buffer_capacity=*/kMaxPrefetchedBlocks};

        auto signal_check_time{std::chrono::steady_clock::now()};
        auto log_time{signal_check_time};

        size_t gas_history_size{0};
        size_t gas_batch_size{0};
        for (BlockNum block_number{start_block}; block_number <= max_block; ++block_number) {
            if (prefetched_blocks.empty()) {
                const auto num_blocks{std::min(size_t(max_block - block_number + 1), kMaxPrefetchedBlocks)};
                SILK_TRACE << "Prefetching " << num_blocks << " blocks start";
                for (BlockNum n{block_number}; n < block_number + num_blocks; ++n) {
                    prefetched_blocks.push_back();
                    const bool success{access_layer.read_block(n, /*read_senders=*/true, prefetched_blocks.back())};
                    if (!success) {
                        return SILKWORM_BLOCK_NOT_FOUND;
                    }
                }
                SILK_TRACE << "Prefetching " << num_blocks << " blocks done";
            }
            const Block& block{prefetched_blocks.front()};

            const auto protocol_rule_set{protocol::rule_set_factory(*chain_config)};
            if (!protocol_rule_set) {
                return SILKWORM_UNKNOWN_CHAIN_ID;
            }
            ExecutionProcessor processor{block, *protocol_rule_set, state_buffer, *chain_config};
            processor.evm().analysis_cache = &analysis_cache;
            processor.evm().state_pool = &state_pool;
            CallTraces traces;
            CallTracer tracer{traces};
            if (write_call_traces) {
                processor.evm().add_tracer(tracer);
            }

            std::vector<Receipt> receipts;
            const auto result{processor.execute_and_write_block(receipts)};
            if (result != ValidationResult::kOk) {
                return SILKWORM_INVALID_BLOCK;
            }

            if (write_receipts) {
                state_buffer.insert_receipts(block.header.number, receipts);
            }
            if (write_call_traces) {
                state_buffer.insert_call_traces(block.header.number, traces);
            }

            if (last_executed_block) {
                *last_executed_block = block.header.number;
            }

            prefetched_blocks.pop_front();

            // Flush whole state buffer or just history if we've reached the target batch sizes in gas units
            if (gas_batch_size >= gas_max_batch_size) {
                SILK_TRACE << log::Args{"buffer", "state", "size", human_size(state_buffer.current_batch_state_size())};
                state_buffer.write_to_db(write_change_sets);
                gas_batch_size = 0;
            } else if (gas_history_size >= gas_max_history_size) {
                SILK_TRACE << log::Args{"buffer", "history", "size", human_size(state_buffer.current_batch_state_size())};
                state_buffer.write_history_to_db(write_change_sets);
                gas_history_size = 0;
            }

            const auto now{std::chrono::steady_clock::now()};
            if (signal_check_time <= now) {
                if (SignalHandler::signalled()) {
                    return SILKWORM_TERMINATION_SIGNAL;
                }
                signal_check_time = now + 5s;
            }
            if (log_time <= now) {
                SILK_INFO << "[4/12 Execution] Executed blocks" << log_args_for_exec_progress(block.header.number);
                log_time = now + 20s;
            }
        }

        state_buffer.write_to_db(write_change_sets);
        return SILKWORM_OK;
    } catch (const mdbx::exception& e) {
        if (mdbx_error_code) {
            *mdbx_error_code = e.error().code();
        }
        return SILKWORM_MDBX_ERROR;
    } catch (const DecodingError&) {
        return SILKWORM_DECODING_ERROR;
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: " << e.what();
        return SILKWORM_INTERNAL_ERROR;
    } catch (...) {
        return SILKWORM_UNKNOWN_ERROR;
    }
}

SILKWORM_EXPORT int silkworm_fini(SilkwormHandle* handle) SILKWORM_NOEXCEPT {
    if (handle != instance.handle) {
        return SILKWORM_INSTANCE_NOT_FOUND;
    }
    const auto snapshot_repository = reinterpret_cast<snapshot::SnapshotRepository*>(handle);
    if (!snapshot_repository) {
        return SILKWORM_INVALID_HANDLE;
    }
    delete snapshot_repository;
    instance.handle = nullptr;
    SignalHandler::reset();
    return SILKWORM_OK;
}
