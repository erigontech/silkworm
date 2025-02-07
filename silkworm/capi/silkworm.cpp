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

#include "silkworm.h"

#include <charconv>
#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <absl/strings/str_split.h>
#include <boost/thread/scoped_thread.hpp>
#include <gsl/util>

#include <silkworm/buildinfo.h>
#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/execution/call_tracer.hpp>
#include <silkworm/core/execution/execution.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/blocks/bodies/body_index.hpp>
#include <silkworm/db/blocks/headers/header_index.hpp>
#include <silkworm/db/blocks/schema_config.hpp>
#include <silkworm/db/blocks/transactions/txn_index.hpp>
#include <silkworm/db/blocks/transactions/txn_to_block_index.hpp>
#include <silkworm/db/buffer.hpp>
#include <silkworm/db/datastore/snapshots/index_builder.hpp>
#include <silkworm/db/datastore/snapshots/segment/segment_reader.hpp>
#include <silkworm/db/datastore/snapshots/snapshot_bundle.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/db/state/schema_config.hpp>
#include <silkworm/execution/domain_state.hpp>
#include <silkworm/execution/remote_state.hpp>
#include <silkworm/execution/state_factory.hpp>
#include <silkworm/infra/common/bounded_buffer.hpp>
#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/common/stopwatch.hpp>
#include <silkworm/infra/concurrency/context_pool_settings.hpp>
#include <silkworm/infra/concurrency/signal_handler.hpp>
#include <silkworm/infra/concurrency/spawn.hpp>
#include <silkworm/infra/concurrency/thread_pool.hpp>
#include <silkworm/infra/grpc/client/client_context_pool.hpp>
#include <silkworm/node/execution/block/block_executor.hpp>
#include <silkworm/node/stagedsync/execution_engine.hpp>
#include <silkworm/rpc/daemon.hpp>
#include <silkworm/rpc/ethbackend/remote_backend.hpp>
#include <silkworm/rpc/ethdb/kv/backend_providers.hpp>

#include "common.hpp"
#include "instance.hpp"
#include "snapshots.hpp"

using namespace std::chrono_literals;
using namespace silkworm;

static constexpr size_t kMaxBlockBufferSize{100};
static constexpr size_t kMaxPrefetchedBlocks{10'240};

using SteadyTimePoint = std::chrono::time_point<std::chrono::steady_clock>;

//! The progress reached by the block execution process
struct ExecutionProgress {
    SteadyTimePoint start_time;
    SteadyTimePoint next_log_time;
    SteadyTimePoint end_time;
    size_t processed_blocks{0};
    size_t processed_transactions{0};
    size_t processed_gas{0};
    float batch_progress_perc{0.0};
};

//! Kind of match to perform between Erigon and Silkworm libmdbx versions
enum class MdbxVersionCheck : uint8_t {
    kNone,      /// no check at all
    kExact,     /// git-describe versions must match perfectly
    kSemantic,  /// compare semantic versions (<M1.m1.p1> == <M2.m2.p2>)
};

static bool is_compatible_mdbx_version(std::string_view their_version, std::string_view our_version, MdbxVersionCheck check) {
    SILK_TRACE << "is_compatible_mdbx_version their_version: " << their_version << " our_version: " << our_version;
    bool compatible{false};
    switch (check) {
        case MdbxVersionCheck::kNone: {
            compatible = true;
        } break;
        case MdbxVersionCheck::kExact: {
            compatible = their_version == our_version;
        } break;
        case MdbxVersionCheck::kSemantic: {
            const std::vector<std::string> their_version_parts = absl::StrSplit(std::string(their_version), '.');
            const std::vector<std::string> our_version_parts = absl::StrSplit(std::string(our_version), '.');
            compatible = (their_version_parts.size() >= 3) &&
                         (our_version_parts.size() >= 3) &&
                         (their_version_parts[0] == our_version_parts[0]) &&
                         (their_version_parts[1] == our_version_parts[1]) &&
                         (their_version_parts[2] == our_version_parts[2]);
        }
    }
    return compatible;
}

//! Generate log arguments for Silkworm library version
static log::Args log_args_for_version() {
    const auto build_info{silkworm_get_buildinfo()};
    return {
        "git_branch",
        std::string(build_info->git_branch),
        "git_tag",
        std::string(build_info->project_version),
        "git_commit",
        std::string(build_info->git_commit_hash)};
}

//! Generate log arguments for execution flush at specified block
static log::Args log_args_for_exec_flush(const db::Buffer& state_buffer, uint64_t max_batch_size, uint64_t current_block) {
    return {
        "batch",
        std::to_string(state_buffer.current_batch_state_size()),
        "max_batch",
        std::to_string(max_batch_size),
        "block",
        std::to_string(current_block)};
}

//! Generate log arguments for execution commit at specified block
static log::Args log_args_for_exec_commit(StopWatch::Duration elapsed, const std::filesystem::path& env_path) {
    return {
        "in",
        StopWatch::format(elapsed),
        "chaindata",
        std::to_string(Directory{env_path}.size())};
}

//! Generate log arguments for execution progress at specified block
static log::Args log_args_for_exec_progress(ExecutionProgress& progress, uint64_t current_block) {
    static auto float_to_string = [](float f) -> std::string {
        const auto size = std::snprintf(nullptr, 0, "%.1f", static_cast<double>(f));
        std::string s(static_cast<size_t>(size + 1), '\0');                               // +1 for null terminator
        std::ignore = std::snprintf(s.data(), s.size(), "%.1f", static_cast<double>(f));  // certain to fit
        return s.substr(0, s.size() - 1);                                                 // remove null terminator
    };

    const auto elapsed{progress.end_time - progress.start_time};
    progress.start_time = progress.end_time;
    const auto duration_seconds{std::chrono::duration_cast<std::chrono::seconds>(elapsed)};
    const auto elapsed_seconds = duration_seconds.count() != 0 ? static_cast<float>(duration_seconds.count()) : 1.0f;
    if (progress.processed_blocks == 0) {
        return {"number", std::to_string(current_block), "db", "waiting..."};
    }
    const auto speed_blocks = static_cast<float>(progress.processed_blocks) / elapsed_seconds;
    const auto speed_transactions = static_cast<float>(progress.processed_transactions) / elapsed_seconds;
    const auto speed_mgas = static_cast<float>(progress.processed_gas) / elapsed_seconds / 1'000'000;
    progress.processed_blocks = 0;
    progress.processed_transactions = 0;
    progress.processed_gas = 0;
    std::stringstream batch_progress_perc;
    batch_progress_perc << std::fixed << std::setprecision(2) << progress.batch_progress_perc * 100 << "%";
    return {
        "number",
        std::to_string(current_block),
        "blk/s",
        float_to_string(speed_blocks),
        "tx/s",
        float_to_string(speed_transactions),
        "Mgas/s",
        float_to_string(speed_mgas),
        "batchProgress",
        batch_progress_perc.str()};
}

static void update_execution_progress(ExecutionProgress& progress, const Block& block, const db::Buffer& state_buffer, size_t max_batch_size) {
    ++progress.processed_blocks;
    progress.processed_transactions += block.transactions.size();
    progress.processed_gas += block.header.gas_used;

    const auto now{std::chrono::steady_clock::now()};
    if (progress.next_log_time <= now) {
        progress.batch_progress_perc = static_cast<float>(state_buffer.current_batch_state_size()) / static_cast<float>(max_batch_size);
        progress.end_time = now;
        log::Info{"[4/12 Execution] Executed blocks",  // NOLINT(*-unused-raii)
                  log_args_for_exec_progress(progress, block.header.number)};
        progress.next_log_time = now + 20s;
    }
}

//! A signal handler guard using RAII pattern to acquire/release signal handling
class SignalHandlerGuard {
  public:
    SignalHandlerGuard() { SignalHandler::init(/*custom_handler=*/{}, /*silent=*/true); }
    ~SignalHandlerGuard() { SignalHandler::reset(); }
};

static bool is_initialized{false};

SILKWORM_EXPORT int silkworm_init(SilkwormHandle* handle, const struct SilkwormSettings* settings) SILKWORM_NOEXCEPT {
    if (!handle) {
        return SILKWORM_INVALID_HANDLE;
    }
    if (!settings) {
        return SILKWORM_INVALID_SETTINGS;
    }
    if (std::strlen(settings->data_dir_path) == 0) {
        return SILKWORM_INVALID_PATH;
    }
    if (!is_compatible_mdbx_version(settings->libmdbx_version, silkworm_libmdbx_version(), MdbxVersionCheck::kExact)) {
        return SILKWORM_INCOMPATIBLE_LIBMDBX;
    }
    if (is_initialized) {
        return SILKWORM_TOO_MANY_INSTANCES;
    }

    is_initialized = true;

    log::Settings log_settings{make_log_settings(settings->log_verbosity)};
    log::init(log_settings);
    log::Info{"Silkworm build info", log_args_for_version()};  // NOLINT(*-unused-raii)

    auto data_dir_path = parse_path(settings->data_dir_path);
    auto snapshots_dir_path = DataDirectory{data_dir_path}.snapshots().path();
    auto blocks_repository = db::blocks::make_blocks_repository(
        snapshots_dir_path,
        /* open = */ false,
        settings->blocks_repo_index_salt);
    auto state_repository = db::state::make_state_repository(
        snapshots_dir_path,
        /* open = */ false,
        settings->state_repo_index_salt);

    // NOLINTNEXTLINE(bugprone-unhandled-exception-at-new)
    *handle = new SilkwormInstance{
        .log_settings = std::move(log_settings),
        .context_pool_settings = {
            .num_contexts = settings->num_contexts > 0 ? settings->num_contexts : silkworm::concurrency::kDefaultNumContexts,
        },
        .data_dir_path = std::move(data_dir_path),
        .node_settings = {},
        .blocks_repository = std::make_unique<snapshots::SnapshotRepository>(std::move(blocks_repository)),
        .state_repository = std::make_unique<snapshots::SnapshotRepository>(std::move(state_repository)),
        .rpcdaemon = {},
        .execution_engine = {},
        .sentry_thread = {},
        .sentry_stop_signal = {},
    };
    return SILKWORM_OK;
}

SILKWORM_EXPORT int silkworm_build_recsplit_indexes(SilkwormHandle handle, struct SilkwormMemoryMappedFile* segments[], size_t len) SILKWORM_NOEXCEPT {
    constexpr int kNeededIndexesToBuildInParallel = 2;

    if (!handle) {
        return SILKWORM_INVALID_HANDLE;
    }

    auto schema = db::blocks::make_blocks_repository_schema();

    std::vector<std::shared_ptr<snapshots::IndexBuilder>> needed_indexes;
    for (size_t i = 0; i < len; ++i) {
        struct SilkwormMemoryMappedFile* segment = segments[i];
        if (!segment) {
            return SILKWORM_INVALID_SNAPSHOT;
        }
        auto segment_region = make_region(*segment);

        const auto snapshot_path = snapshots::SnapshotPath::parse(segment->file_path);
        if (!snapshot_path) {
            return SILKWORM_INVALID_PATH;
        }

        auto names = schema.entity_name_by_path(*snapshot_path);
        if (!names) {
            return SILKWORM_INVALID_PATH;
        }
        datastore::EntityName name = names->second;
        {
            if (name == db::blocks::kHeaderSegmentName) {
                auto index = std::make_shared<snapshots::IndexBuilder>(snapshots::HeaderIndex::make(*snapshot_path, segment_region));
                needed_indexes.push_back(index);
            } else if (name == db::blocks::kBodySegmentName) {
                auto index = std::make_shared<snapshots::IndexBuilder>(snapshots::BodyIndex::make(*snapshot_path, segment_region));
                needed_indexes.push_back(index);
            } else if (name == db::blocks::kTxnSegmentName) {
                auto bodies_segment_path = snapshot_path->related_path(std::string{db::blocks::kBodySegmentTag}, db::blocks::kSegmentExtension);
                auto bodies_file = std::find_if(segments, segments + len, [&](SilkwormMemoryMappedFile* file) -> bool {
                    return snapshots::SnapshotPath::parse(file->file_path) == bodies_segment_path;
                });

                if (bodies_file < segments + len) {
                    auto bodies_segment_region = make_region(**bodies_file);

                    auto index = std::make_shared<snapshots::IndexBuilder>(snapshots::TransactionIndex::make(
                        bodies_segment_path, bodies_segment_region, *snapshot_path, segment_region));
                    needed_indexes.push_back(index);

                    index = std::make_shared<snapshots::IndexBuilder>(snapshots::TransactionToBlockIndex::make(
                        bodies_segment_path, bodies_segment_region, *snapshot_path, segment_region));
                    needed_indexes.push_back(index);
                }
            } else {
                SILKWORM_ASSERT(false);
            }
        }
    }

    if (needed_indexes.size() < kNeededIndexesToBuildInParallel) {
        // sequential build
        for (const auto& index : needed_indexes) {
            index->build();
        }
    } else {
        // parallel build
        ThreadPool workers;

        // Create worker tasks for missing indexes
        for (const auto& index : needed_indexes) {
            workers.push_task([=]() {
                try {
                    SILK_INFO << "Build index: " << index->path().filename() << " start";
                    index->build();
                    SILK_INFO << "Build index: " << index->path().filename() << " end";
                } catch (const std::exception& ex) {
                    SILK_CRIT << "Build index: " << index->path().filename() << " failed [" << ex.what() << "]";
                }
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

SILKWORM_EXPORT int silkworm_add_blocks_snapshot(SilkwormHandle handle, SilkwormChainSnapshot* snapshot) SILKWORM_NOEXCEPT {
    if (!handle || !handle->blocks_repository) {
        return SILKWORM_INVALID_HANDLE;
    }
    if (!snapshot) {
        return SILKWORM_INVALID_SNAPSHOT;
    }
    const SilkwormHeadersSnapshot& hs = snapshot->headers;
    if (!hs.segment.file_path || !hs.header_hash_index.file_path) {
        return SILKWORM_INVALID_PATH;
    }
    const auto headers_segment_path = snapshots::SnapshotPath::parse(hs.segment.file_path);
    if (!headers_segment_path) {
        return SILKWORM_INVALID_PATH;
    }
    snapshots::segment::SegmentFileReader header_segment{*headers_segment_path, make_region(hs.segment)};
    snapshots::rec_split::AccessorIndex idx_header_hash{headers_segment_path->related_path_ext(db::blocks::kIdxExtension), make_region(hs.header_hash_index)};

    const SilkwormBodiesSnapshot& bs = snapshot->bodies;
    if (!bs.segment.file_path || !bs.block_num_index.file_path) {
        return SILKWORM_INVALID_PATH;
    }
    const auto bodies_segment_path = snapshots::SnapshotPath::parse(bs.segment.file_path);
    if (!bodies_segment_path) {
        return SILKWORM_INVALID_PATH;
    }
    snapshots::segment::SegmentFileReader body_segment{*bodies_segment_path, make_region(bs.segment)};
    snapshots::rec_split::AccessorIndex idx_body_number{bodies_segment_path->related_path_ext(db::blocks::kIdxExtension), make_region(bs.block_num_index)};

    const SilkwormTransactionsSnapshot& ts = snapshot->transactions;
    if (!ts.segment.file_path || !ts.tx_hash_index.file_path || !ts.tx_hash_2_block_index.file_path) {
        return SILKWORM_INVALID_PATH;
    }
    const auto transactions_segment_path = snapshots::SnapshotPath::parse(ts.segment.file_path);
    if (!transactions_segment_path) {
        return SILKWORM_INVALID_PATH;
    }
    snapshots::segment::SegmentFileReader txn_segment{*transactions_segment_path, make_region(ts.segment)};
    snapshots::rec_split::AccessorIndex idx_txn_hash{transactions_segment_path->related_path_ext(db::blocks::kIdxExtension), make_region(ts.tx_hash_index)};
    snapshots::rec_split::AccessorIndex idx_txn_hash_2_block{transactions_segment_path->related_path(std::string{db::blocks::kIdxTxnHash2BlockTag}, db::blocks::kIdxExtension), make_region(ts.tx_hash_2_block_index)};

    auto bundle_data_provider = [&]() -> snapshots::SnapshotBundleEntityData {
        snapshots::SnapshotBundleEntityData data;

        data.segments.emplace(db::blocks::kHeaderSegmentName, std::move(header_segment));
        data.accessor_indexes.emplace(db::blocks::kIdxHeaderHashName, std::move(idx_header_hash));

        data.segments.emplace(db::blocks::kBodySegmentName, std::move(body_segment));
        data.accessor_indexes.emplace(db::blocks::kIdxBodyNumberName, std::move(idx_body_number));

        data.segments.emplace(db::blocks::kTxnSegmentName, std::move(txn_segment));
        data.accessor_indexes.emplace(db::blocks::kIdxTxnHashName, std::move(idx_txn_hash));
        data.accessor_indexes.emplace(db::blocks::kIdxTxnHash2BlockName, std::move(idx_txn_hash_2_block));

        return data;
    };
    snapshots::SnapshotBundleData bundle_data;
    bundle_data.entities.emplace(snapshots::Schema::kDefaultEntityName, bundle_data_provider());

    snapshots::SnapshotBundle bundle{
        headers_segment_path->step_range(),
        std::move(bundle_data),
    };
    handle->blocks_repository->add_snapshot_bundle(std::move(bundle));
    return SILKWORM_OK;
}

SILKWORM_EXPORT int silkworm_add_state_snapshot(SilkwormHandle handle, const SilkwormStateSnapshot* snapshot) SILKWORM_NOEXCEPT {
    if (!handle || !handle->state_repository) {
        return SILKWORM_INVALID_HANDLE;
    }
    if (!snapshot) {
        return SILKWORM_INVALID_SNAPSHOT;
    }
    if (!handle->state_repository->index_salt()) {
        return SILKWORM_INTERNAL_ERROR;
    }
    auto snapshot_bundle = build_state_snapshot(snapshot, *handle->state_repository->index_salt());
    if (!snapshot_bundle) {
        return snapshot_bundle.error();
    }
    handle->state_repository->add_snapshot_bundle(std::move(*snapshot_bundle));
    return SILKWORM_OK;
}

SILKWORM_EXPORT const char* silkworm_libmdbx_version() SILKWORM_NOEXCEPT {
    return ::mdbx::get_version().git.describe;
}

class BlockProvider {
    static constexpr size_t kTxnRefreshThreshold{100};

  public:
    BlockProvider(BoundedBuffer<std::optional<Block>>* block_buffer,
                  datastore::kvdb::ROAccess db_access,
                  db::DataModelFactory data_model_factory,
                  BlockNum start_block, BlockNum max_block)
        : block_buffer_{block_buffer},
          db_access_{std::move(db_access)},
          data_model_factory_{std::move(data_model_factory)},
          start_block_{start_block},
          max_block_{max_block} {}

    void operator()() {
        auto txn = db_access_.start_ro_tx();
        db::DataModel access_layer = data_model_factory_(txn);

        BlockNum current_block{start_block_};
        size_t refresh_counter{kTxnRefreshThreshold};

        try {
            Block block;
            while (current_block <= max_block_ && !block_buffer_->is_stopped()) {
                const bool success{access_layer.read_block(current_block, /*read_senders=*/true, block)};
                if (!success) {
                    block_buffer_->push_front(std::nullopt);
                    return;
                }
                block_buffer_->push_front(std::move(block));
                ++current_block;

                if (--refresh_counter == 0) {
                    txn.abort();
                    txn = db_access_.start_ro_tx();
                    refresh_counter = kTxnRefreshThreshold;
                }
            }
        } catch (const boost::thread_interrupted&) {
            SILK_TRACE << "thread_interrupted in block provider thread";
        } catch (const std::exception& ex) {
            SILK_WARN << "unexpected exception in block provider thread: what=" << ex.what();
        } catch (...) {
            SILK_ERROR << "unknown exception in block provider thread";
        }
    }

  private:
    BoundedBuffer<std::optional<Block>>* block_buffer_;
    datastore::kvdb::ROAccess db_access_;
    db::DataModelFactory data_model_factory_;
    BlockNum start_block_;
    BlockNum max_block_;
};

inline bool signal_check(SteadyTimePoint& signal_check_time) {
    const auto now{std::chrono::steady_clock::now()};
    if (signal_check_time <= now) {
        if (SignalHandler::signalled()) {
            return true;
        }
        signal_check_time += 5s;
    }

    return false;
}

SILKWORM_EXPORT
int silkworm_execute_blocks_ephemeral(SilkwormHandle handle, MDBX_txn* mdbx_txn, uint64_t chain_id,
                                      uint64_t start_block, uint64_t max_block, uint64_t batch_size,
                                      bool write_change_sets, bool write_receipts, bool write_call_traces,
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
    const auto chain_info = kKnownChainConfigs.find(chain_id);
    if (!chain_info) {
        return SILKWORM_UNKNOWN_CHAIN_ID;
    }
    SignalHandlerGuard signal_guard;

    try {
        auto txn = datastore::kvdb::RWTxnUnmanaged{mdbx_txn};

        db::Buffer state_buffer{txn, std::make_unique<db::BufferFullDataModel>(db::DataModel{txn, *handle->blocks_repository})};
        state_buffer.set_memory_limit(batch_size);

        const size_t max_batch_size{batch_size};
        auto signal_check_time{std::chrono::steady_clock::now()};

        BlockNum block_num{start_block};
        BlockNum batch_start_block_num{start_block};
        BlockNum last_block_num = 0;
        db::DataModel da_layer{txn, *handle->blocks_repository};

        AnalysisCache analysis_cache{execution::block::BlockExecutor::kDefaultAnalysisCacheSize};
        execution::block::BlockExecutor block_executor{*chain_info, write_receipts, write_call_traces, write_change_sets};
        const auto now = std::chrono::steady_clock::now();
        ExecutionProgress execution_progress{.start_time = now, .next_log_time = now + 20s};
        ValidationResult last_exec_result = ValidationResult::kOk;
        boost::circular_buffer<Block> prefetched_blocks{/*buffer_capacity=*/kMaxPrefetchedBlocks};

        while (block_num <= max_block) {
            while (block_num <= max_block) {
                if (prefetched_blocks.empty()) {
                    const auto num_blocks{std::min(size_t{max_block - block_num + 1}, kMaxPrefetchedBlocks)};
                    SILK_TRACE << "Prefetching " << num_blocks << " blocks start";
                    for (BlockNum n{block_num}; n < block_num + num_blocks; ++n) {
                        prefetched_blocks.push_back();
                        const bool success{da_layer.read_block(n, /*read_senders=*/true, prefetched_blocks.back())};
                        if (!success) {
                            return SILKWORM_BLOCK_NOT_FOUND;
                        }
                    }
                    SILK_TRACE << "Prefetching " << num_blocks << " blocks done";
                }
                const Block& block{prefetched_blocks.front()};

                try {
                    last_exec_result = block_executor.execute_single(block, state_buffer, analysis_cache);
                    update_execution_progress(execution_progress, block, state_buffer, max_batch_size);
                } catch (const db::Buffer::MemoryLimitError&) {
                    // infinite loop detection, buffer memory limit reached but no progress
                    if (batch_start_block_num == block_num) {
                        SILK_ERROR << "Buffer memory limit too small to execute a single block (block_num=" << block_num << ")";
                        return SILKWORM_INTERNAL_ERROR;
                    }

                    // batch done
                    batch_start_block_num = block_num;
                    break;
                }
                if (last_exec_result != ValidationResult::kOk) {
                    // firstly, persist the work done so far, then return SILKWORM_INVALID_BLOCK
                    break;
                }

                if (signal_check(signal_check_time)) {
                    return SILKWORM_TERMINATION_SIGNAL;
                }

                last_block_num = block_num;
                ++block_num;
                prefetched_blocks.pop_front();
            }

            log::Info{"[4/12 Execution] Flushing state",  // NOLINT(*-unused-raii)
                      log_args_for_exec_flush(state_buffer, max_batch_size, last_block_num)};
            state_buffer.write_state_to_db();
            // Always save the Execution stage progress when state batch is flushed
            db::stages::write_stage_progress(txn, db::stages::kExecutionKey, last_block_num);

            if (last_executed_block) {
                *last_executed_block = last_block_num;
            }

            if (last_exec_result != ValidationResult::kOk) {
                return SILKWORM_INVALID_BLOCK;
            }
        }
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
        SILK_ERROR << "unknown exception";
        return SILKWORM_UNKNOWN_ERROR;
    }
}

SILKWORM_EXPORT
int silkworm_execute_blocks_perpetual(SilkwormHandle handle, MDBX_env* mdbx_env, uint64_t chain_id,
                                      uint64_t start_block, uint64_t max_block, uint64_t batch_size,
                                      bool write_change_sets, bool write_receipts, bool write_call_traces,
                                      uint64_t* last_executed_block, int* mdbx_error_code) SILKWORM_NOEXCEPT {
    if (!handle) {
        return SILKWORM_INVALID_HANDLE;
    }
    if (!mdbx_env) {
        return SILKWORM_INVALID_MDBX_ENV;
    }
    if (start_block > max_block) {
        return SILKWORM_INVALID_BLOCK_RANGE;
    }
    const auto chain_info = kKnownChainConfigs.find(chain_id);
    if (!chain_info) {
        return SILKWORM_UNKNOWN_CHAIN_ID;
    }
    SignalHandlerGuard signal_guard;

    try {
        // Wrap MDBX env into an internal *unmanaged* env, i.e. MDBX env is only used but its lifecycle is untouched
        datastore::kvdb::EnvUnmanaged unmanaged_env{mdbx_env};
        const auto env_path = unmanaged_env.get_path();
        handle->chaindata = std::make_unique<datastore::kvdb::DatabaseUnmanaged>(
            db::DataStore::make_chaindata_database(std::move(unmanaged_env)));
        auto& chaindata = *handle->chaindata;

        datastore::kvdb::RWAccess rw_access = chaindata.access_rw();
        auto txn = rw_access.start_rw_tx();

        db::Buffer state_buffer{txn, std::make_unique<db::BufferFullDataModel>(db::DataModel{txn, *handle->blocks_repository})};
        state_buffer.set_memory_limit(batch_size);

        BoundedBuffer<std::optional<Block>> block_buffer{kMaxBlockBufferSize};
        [[maybe_unused]] auto _ = gsl::finally([&block_buffer] { block_buffer.terminate_and_release_all(); });

        db::DataStoreRef data_store{
            chaindata.ref(),
            *handle->blocks_repository,
            *handle->state_repository,
        };
        db::DataModelFactory data_model_factory{std::move(data_store)};

        BlockProvider block_provider{
            &block_buffer,
            chaindata.access_ro(),
            std::move(data_model_factory),
            start_block,
            max_block,
        };
        boost::strict_scoped_thread<boost::interrupt_and_join_if_joinable> block_provider_thread(block_provider);

        const size_t max_batch_size{batch_size};
        auto signal_check_time{std::chrono::steady_clock::now()};

        std::optional<Block> block;
        BlockNum block_num{start_block};
        BlockNum batch_start_block_num{start_block};
        BlockNum last_block_num = 0;
        AnalysisCache analysis_cache{execution::block::BlockExecutor::kDefaultAnalysisCacheSize};
        execution::block::BlockExecutor block_executor{*chain_info, write_receipts, write_call_traces, write_change_sets};
        const auto now = std::chrono::steady_clock::now();
        ExecutionProgress execution_progress{.start_time = now, .next_log_time = now + 20s};
        ValidationResult last_exec_result = ValidationResult::kOk;

        while (block_num <= max_block) {
            while (block_num <= max_block) {
                block_buffer.peek_back(&block);
                if (!block) {
                    return SILKWORM_BLOCK_NOT_FOUND;
                }
                SILKWORM_ASSERT(block->header.number == block_num);

                try {
                    last_exec_result = block_executor.execute_single(*block, state_buffer, analysis_cache);
                    update_execution_progress(execution_progress, *block, state_buffer, max_batch_size);
                } catch (const db::Buffer::MemoryLimitError&) {
                    // infinite loop detection, buffer memory limit reached but no progress
                    if (batch_start_block_num == block_num) {
                        SILK_ERROR << "Buffer memory limit too small to execute a single block (block_num=" << block_num << ")";
                        return SILKWORM_INTERNAL_ERROR;
                    }

                    // batch done
                    batch_start_block_num = block_num;
                    break;
                }

                if (last_exec_result != ValidationResult::kOk) {
                    // firstly, persist the work done so far, then return SILKWORM_INVALID_BLOCK
                    break;
                }

                if (signal_check(signal_check_time)) {
                    return SILKWORM_TERMINATION_SIGNAL;
                }

                last_block_num = block_num;
                ++block_num;
                block_buffer.pop_back(&block);
            }

            StopWatch sw{/*auto_start=*/true};
            log::Info{"[4/12 Execution] Flushing state",  // NOLINT(*-unused-raii)
                      log_args_for_exec_flush(state_buffer, max_batch_size, last_block_num)};
            state_buffer.write_state_to_db();
            // Always save the Execution stage progress when state batch is flushed
            db::stages::write_stage_progress(txn, db::stages::kExecutionKey, last_block_num);
            // Commit and renew only in case of internally managed transaction
            txn.commit_and_renew();
            const auto elapsed_time_and_duration = sw.stop();
            log::Info("[4/12 Execution] Commit state+history",  // NOLINT(*-unused-raii)
                      log_args_for_exec_commit(elapsed_time_and_duration.second, env_path));

            if (last_executed_block) {
                *last_executed_block = last_block_num;
            }

            if (last_exec_result != ValidationResult::kOk) {
                return SILKWORM_INVALID_BLOCK;
            }
        }
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
        SILK_ERROR << "unknown exception";
        return SILKWORM_UNKNOWN_ERROR;
    }
}

SILKWORM_EXPORT int silkworm_execute_txn(SilkwormHandle handle, MDBX_txn* mdbx_tx, uint64_t block_num, struct SilkwormBytes32 block_hash, uint64_t txn_index, uint64_t txn_num, uint64_t* gas_used, uint64_t* blob_gas_used) SILKWORM_NOEXCEPT {
    log::Info{"silkworm_execute_txn", {"block_num", std::to_string(block_num), "txn_index", std::to_string(txn_index)}};
    if (!handle) {
        return SILKWORM_INVALID_HANDLE;
    }

    if (!mdbx_tx) {
        return SILKWORM_INVALID_MDBX_TXN;
    }

    if (gas_used) {
        *gas_used = 0;
    }

    if (blob_gas_used) {
        *blob_gas_used = 0;
    }

    silkworm::Hash block_header_hash{};
    memcpy(block_header_hash.bytes, block_hash.bytes, sizeof(block_hash.bytes));
    BlockNum block_number{block_num};
    TxnId txn_id_{txn_num};

    auto unmanaged_tx = datastore::kvdb::RWTxnUnmanaged{mdbx_tx};
    auto unmanaged_env = silkworm::datastore::kvdb::EnvUnmanaged{::mdbx_txn_env(mdbx_tx)};
    auto chain_db = db::DataStore::make_chaindata_database(std::move(unmanaged_env));
    auto db_ref = chain_db.ref();
    auto state = silkworm::execution::DomainState{txn_id_, unmanaged_tx, db_ref, *handle->blocks_repository, *handle->state_repository};
    if (!handle->chain_config) {
        handle->chain_config = db::read_chain_config(unmanaged_tx);
    }

    // TODO: cache block, also consider preloading
    silkworm::Block block{};
    auto block_read_ok = state.read_body(block_number, block_header_hash, block);
    if (!block_read_ok) {
        SILK_ERROR << "Block not found"
                   << " block_number: " << block_number << " block_hash: " << block_header_hash;
        return SILKWORM_INVALID_BLOCK;
    }
    auto header = state.read_header(block_number, block_header_hash);
    if (!header) {
        SILK_ERROR << "Header not found"
                   << " block_number: " << block_number << " block_hash: " << block_header_hash;
        return SILKWORM_INVALID_BLOCK;
    }
    block.header = header.value();

    if (txn_index >= block.transactions.size()) {
        SILK_ERROR << "Transaction not found"
                   << " txn_index: " << txn_index;
        return SILKWORM_INVALID_BLOCK;
    }

    auto& transaction = block.transactions[txn_index];

    auto protocol_rule_set_{protocol::rule_set_factory(*handle->chain_config)};
    ExecutionProcessor processor{block, *protocol_rule_set_, state, *handle->chain_config, false};
    // TODO: add analysis cache, check block exec for more

    silkworm::Receipt receipt{};
    const ValidationResult err{protocol::validate_transaction(transaction, processor.intra_block_state(), processor.available_gas())};
    if (err != ValidationResult::kOk) {
        return SILKWORM_INVALID_BLOCK;
    }
    processor.execute_transaction(transaction, receipt);
    state.insert_receipts(block_number, std::vector<silkworm::Receipt>{receipt});

    if (gas_used) {
        *gas_used = receipt.cumulative_gas_used;
    }
    if (blob_gas_used) {
        *blob_gas_used = transaction.total_blob_gas();
    }

    return SILKWORM_OK;
}

SILKWORM_EXPORT int silkworm_fini(SilkwormHandle handle) SILKWORM_NOEXCEPT {
    if (!handle) {
        return SILKWORM_INVALID_HANDLE;
    }
    if (!handle->blocks_repository) {
        return SILKWORM_INVALID_HANDLE;
    }
    delete handle;

    is_initialized = false;

    return SILKWORM_OK;
}
