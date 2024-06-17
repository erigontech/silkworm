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
#include <silkworm/db/bodies/body_index.hpp>
#include <silkworm/db/buffer.hpp>
#include <silkworm/db/headers/header_index.hpp>
#include <silkworm/db/snapshot_bundle_factory_impl.hpp>
#include <silkworm/db/snapshots/index.hpp>
#include <silkworm/db/snapshots/index_builder.hpp>
#include <silkworm/db/snapshots/snapshot_reader.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/db/transactions/txn_index.hpp>
#include <silkworm/db/transactions/txn_to_block_index.hpp>
#include <silkworm/infra/common/bounded_buffer.hpp>
#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/common/stopwatch.hpp>
#include <silkworm/infra/concurrency/context_pool_settings.hpp>
#include <silkworm/infra/concurrency/signal_handler.hpp>
#include <silkworm/infra/concurrency/thread_pool.hpp>

#include "common.hpp"
#include "instance.hpp"

using namespace std::chrono_literals;
using namespace silkworm;

static MemoryMappedRegion make_region(const SilkwormMemoryMappedFile& mmf) {
    return {mmf.memory_address, mmf.memory_length};
}

static constexpr size_t kMaxBlockBufferSize{100};
static constexpr size_t kAnalysisCacheSize{5'000};
static constexpr size_t kMaxPrefetchedBlocks{10'240};

using SteadyTimePoint = std::chrono::time_point<std::chrono::steady_clock>;

//! The progress reached by the block execution process
struct ExecutionProgress {
    SteadyTimePoint start_time;
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
static log::Args log_args_for_exec_commit(StopWatch::Duration elapsed, const std::filesystem::path& db_path) {
    return {
        "in",
        StopWatch::format(elapsed),
        "chaindata",
        std::to_string(Directory{db_path}.size())};
}

//! Generate log arguments for execution progress at specified block
static log::Args log_args_for_exec_progress(ExecutionProgress& progress, uint64_t current_block) {
    static auto float_to_string = [](float f) -> std::string {
        const auto size = std::snprintf(nullptr, 0, "%.1f", static_cast<double>(f));
        std::string s(static_cast<size_t>(size + 1), '\0');                       // +1 for null terminator
        (void)std::snprintf(s.data(), s.size(), "%.1f", static_cast<double>(f));  // certain to fit
        return s.substr(0, s.size() - 1);                                         // remove null terminator
    };

    const auto elapsed{progress.end_time - progress.start_time};
    progress.start_time = progress.end_time;
    const auto duration_seconds{std::chrono::duration_cast<std::chrono::seconds>(elapsed)};
    const auto elapsed_seconds = duration_seconds.count() != 0 ? float(duration_seconds.count()) : 1.0f;
    if (progress.processed_blocks == 0) {
        return {"number", std::to_string(current_block), "db", "waiting..."};
    }
    const auto speed_blocks = float(progress.processed_blocks) / elapsed_seconds;
    const auto speed_transactions = float(progress.processed_transactions) / elapsed_seconds;
    const auto speed_mgas = float(progress.processed_gas) / elapsed_seconds / 1'000'000;
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

    auto snapshot_bundle_factory = std::make_unique<db::SnapshotBundleFactoryImpl>();
    auto snapshot_repository = std::make_unique<snapshots::SnapshotRepository>(snapshots::SnapshotSettings{}, std::move(snapshot_bundle_factory));
    db::DataModel::set_snapshot_repository(snapshot_repository.get());

    // NOLINTNEXTLINE(bugprone-unhandled-exception-at-new)
    *handle = new SilkwormInstance{
        .log_settings = std::move(log_settings),
        .context_pool_settings = {
            .num_contexts = settings->num_contexts > 0 ? settings->num_contexts : silkworm::concurrency::kDefaultNumContexts,
        },
        .data_dir_path = parse_path(settings->data_dir_path),
        .snapshot_repository = std::move(snapshot_repository),
        .rpcdaemon = {},
        .sentry_thread = {},
        .sentry_stop_signal = {},
    };
    return SILKWORM_OK;
}

SILKWORM_EXPORT int silkworm_build_recsplit_indexes(SilkwormHandle handle, struct SilkwormMemoryMappedFile* snapshots[], size_t len) SILKWORM_NOEXCEPT {
    const int kNeededIndexesToBuildInParallel = 2;

    if (!handle) {
        return SILKWORM_INVALID_HANDLE;
    }

    std::vector<std::shared_ptr<snapshots::IndexBuilder>> needed_indexes;
    for (size_t i = 0; i < len; i++) {
        struct SilkwormMemoryMappedFile* snapshot = snapshots[i];
        if (!snapshot) {
            return SILKWORM_INVALID_SNAPSHOT;
        }
        auto snapshot_region = make_region(*snapshot);

        const auto snapshot_path = snapshots::SnapshotPath::parse(snapshot->file_path);
        if (!snapshot_path) {
            return SILKWORM_INVALID_PATH;
        }

        std::shared_ptr<snapshots::IndexBuilder> index;
        switch (snapshot_path->type()) {
            case snapshots::SnapshotType::headers: {
                index = std::make_shared<snapshots::IndexBuilder>(snapshots::HeaderIndex::make(*snapshot_path, snapshot_region));
                needed_indexes.push_back(index);
                break;
            }
            case snapshots::SnapshotType::bodies: {
                index = std::make_shared<snapshots::IndexBuilder>(snapshots::BodyIndex::make(*snapshot_path, snapshot_region));
                needed_indexes.push_back(index);
                break;
            }
            case snapshots::SnapshotType::transactions: {
                auto bodies_segment_path = snapshots::TransactionIndex::bodies_segment_path(*snapshot_path);
                auto bodies_file = std::find_if(snapshots, snapshots + len, [&](SilkwormMemoryMappedFile* file) -> bool {
                    return snapshots::SnapshotPath::parse(file->file_path) == bodies_segment_path;
                });

                if (bodies_file < snapshots + len) {
                    auto bodies_segment_region = make_region(**bodies_file);

                    index = std::make_shared<snapshots::IndexBuilder>(snapshots::TransactionIndex::make(
                        bodies_segment_path, bodies_segment_region, *snapshot_path, snapshot_region));
                    needed_indexes.push_back(index);

                    index = std::make_shared<snapshots::IndexBuilder>(snapshots::TransactionToBlockIndex::make(
                        bodies_segment_path, bodies_segment_region, *snapshot_path, snapshot_region));
                    needed_indexes.push_back(index);
                }
                break;
            }
            default: {
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

SILKWORM_EXPORT int silkworm_add_snapshot(SilkwormHandle handle, SilkwormChainSnapshot* snapshot) SILKWORM_NOEXCEPT {
    if (!handle || !handle->snapshot_repository) {
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
    snapshots::Snapshot header_snapshot{*headers_segment_path, make_region(hs.segment)};
    snapshots::Index idx_header_hash{headers_segment_path->index_file(), make_region(hs.header_hash_index)};

    const SilkwormBodiesSnapshot& bs = snapshot->bodies;
    if (!bs.segment.file_path || !bs.block_num_index.file_path) {
        return SILKWORM_INVALID_PATH;
    }
    const auto bodies_segment_path = snapshots::SnapshotPath::parse(bs.segment.file_path);
    if (!bodies_segment_path) {
        return SILKWORM_INVALID_PATH;
    }
    snapshots::Snapshot body_snapshot{*bodies_segment_path, make_region(bs.segment)};
    snapshots::Index idx_body_number{bodies_segment_path->index_file(), make_region(bs.block_num_index)};

    const SilkwormTransactionsSnapshot& ts = snapshot->transactions;
    if (!ts.segment.file_path || !ts.tx_hash_index.file_path || !ts.tx_hash_2_block_index.file_path) {
        return SILKWORM_INVALID_PATH;
    }
    const auto transactions_segment_path = snapshots::SnapshotPath::parse(ts.segment.file_path);
    if (!transactions_segment_path) {
        return SILKWORM_INVALID_PATH;
    }
    snapshots::Snapshot txn_snapshot{*transactions_segment_path, make_region(ts.segment)};
    snapshots::Index idx_txn_hash{transactions_segment_path->index_file_for_type(snapshots::SnapshotType::transactions), make_region(ts.tx_hash_index)};
    snapshots::Index idx_txn_hash_2_block{transactions_segment_path->index_file_for_type(snapshots::SnapshotType::transactions_to_block), make_region(ts.tx_hash_2_block_index)};

    snapshots::SnapshotBundle bundle{
        .header_snapshot = std::move(header_snapshot),
        .idx_header_hash = std::move(idx_header_hash),

        .body_snapshot = std::move(body_snapshot),
        .idx_body_number = std::move(idx_body_number),

        .txn_snapshot = std::move(txn_snapshot),
        .idx_txn_hash = std::move(idx_txn_hash),
        .idx_txn_hash_2_block = std::move(idx_txn_hash_2_block),
    };
    handle->snapshot_repository->add_snapshot_bundle(std::move(bundle));
    return SILKWORM_OK;
}

SILKWORM_EXPORT const char* silkworm_libmdbx_version() SILKWORM_NOEXCEPT {
    return ::mdbx::get_version().git.describe;
}

class BlockProvider {
    static constexpr size_t kTxnRefreshThreshold{100};

  public:
    BlockProvider(BoundedBuffer<std::optional<Block>>* block_buffer,
                  mdbx::env env,
                  BlockNum start_block, BlockNum max_block)
        : block_buffer_{block_buffer},
          env_{std::move(env)},
          start_block_{start_block},
          max_block_{max_block} {}

    void operator()() {
        db::ROTxnManaged txn{env_};
        db::DataModel access_layer{txn};

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
                    txn = db::ROTxnManaged{env_};
                    refresh_counter = kTxnRefreshThreshold;
                }
            }
        } catch (const boost::thread_interrupted& ti) {
            SILK_TRACE << "thread_interrupted in block provider thread";
        } catch (const std::exception& ex) {
            SILK_WARN << "unexpected exception in block provider thread: what=" << ex.what();
        } catch (...) {
            SILK_ERROR << "unknown exception in block provider thread";
        }
    }

  private:
    BoundedBuffer<std::optional<Block>>* block_buffer_;
    mdbx::env env_;
    BlockNum start_block_;
    BlockNum max_block_;
};

class BlockExecutor {
  public:
    BlockExecutor(const ChainConfig* chain_config, bool write_receipts, bool write_call_traces, bool write_change_sets, size_t max_batch_size)
        : chain_config_{chain_config},
          protocol_rule_set_{protocol::rule_set_factory(*chain_config_)},
          write_receipts_{write_receipts},
          write_call_traces_{write_call_traces},
          write_change_sets_{write_change_sets},
          analysis_cache_{kAnalysisCacheSize},
          state_pool_{},
          progress_{.start_time = std::chrono::steady_clock::now()},
          log_time_{progress_.start_time + 20s},
          max_batch_size_{max_batch_size} {}

    silkworm::ValidationResult execute_single(const silkworm::Block& block, silkworm::db::Buffer& state_buffer) {
        ExecutionProcessor processor{block, *protocol_rule_set_, state_buffer, *chain_config_};
        processor.evm().analysis_cache = &analysis_cache_;
        processor.evm().state_pool = &state_pool_;

        CallTraces traces;
        CallTracer tracer{traces};
        if (write_call_traces_) {
            processor.evm().add_tracer(tracer);
        }

        std::vector<Receipt> receipts;
        if (const ValidationResult res = processor.execute_block(receipts); res != ValidationResult::kOk) {
            return res;
        }

        processor.flush_state();

        if (write_receipts_) {
            state_buffer.insert_receipts(block.header.number, receipts);
        }
        if (write_call_traces_) {
            state_buffer.insert_call_traces(block.header.number, traces);
        }

        state_buffer.write_history_to_db(write_change_sets_);

        progress_.processed_blocks++;
        progress_.processed_transactions += block.transactions.size();
        progress_.processed_gas += block.header.gas_used;

        const auto now{std::chrono::steady_clock::now()};
        if (log_time_ <= now) {
            progress_.batch_progress_perc = float(state_buffer.current_batch_state_size()) / float(max_batch_size_);
            progress_.end_time = now;
            log::Info{"[4/12 Execution] Executed blocks",  // NOLINT(*-unused-raii)
                      log_args_for_exec_progress(progress_, block.header.number)};
            log_time_ = now + 20s;
        }

        return ValidationResult::kOk;
    }

  private:
    const ChainConfig* chain_config_;
    silkworm::protocol::RuleSetPtr protocol_rule_set_;
    bool write_receipts_;
    bool write_call_traces_;
    bool write_change_sets_;
    AnalysisCache analysis_cache_;
    ObjectPool<evmone::ExecutionState> state_pool_;
    ExecutionProgress progress_;
    SteadyTimePoint log_time_;
    const size_t max_batch_size_;
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
        auto txn = db::RWTxnUnmanaged{mdbx_txn};

        db::Buffer state_buffer{txn};
        state_buffer.set_memory_limit(batch_size);

        const size_t max_batch_size{batch_size};
        auto signal_check_time{std::chrono::steady_clock::now()};

        BlockNum block_number{start_block};
        BlockNum last_block_number = 0;
        db::DataModel da_layer{txn};
        BlockExecutor block_executor{*chain_info, write_receipts, write_call_traces, write_change_sets, max_batch_size};
        ValidationResult last_exec_result = ValidationResult::kOk;
        boost::circular_buffer<Block> prefetched_blocks{/*buffer_capacity=*/kMaxPrefetchedBlocks};

        while (block_number <= max_block) {
            while (block_number <= max_block) {
                if (prefetched_blocks.empty()) {
                    const auto num_blocks{std::min(size_t(max_block - block_number + 1), kMaxPrefetchedBlocks)};
                    SILK_TRACE << "Prefetching " << num_blocks << " blocks start";
                    for (BlockNum n{block_number}; n < block_number + num_blocks; ++n) {
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
                    last_exec_result = block_executor.execute_single(block, state_buffer);
                } catch (const db::Buffer::MemoryLimitError&) {
                    // batch done
                    break;
                }
                if (last_exec_result != ValidationResult::kOk) {
                    // firstly, persist the work done so far, then return SILKWORM_INVALID_BLOCK
                    break;
                }

                if (signal_check(signal_check_time)) {
                    return SILKWORM_TERMINATION_SIGNAL;
                }

                last_block_number = block_number;
                ++block_number;
                prefetched_blocks.pop_front();
            }

            log::Info{"[4/12 Execution] Flushing state",  // NOLINT(*-unused-raii)
                      log_args_for_exec_flush(state_buffer, max_batch_size, last_block_number)};
            state_buffer.write_state_to_db();
            // Always save the Execution stage progress when state batch is flushed
            db::stages::write_stage_progress(txn, db::stages::kExecutionKey, last_block_number);

            if (last_executed_block) {
                *last_executed_block = last_block_number;
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
        db::EnvUnmanaged unmanaged_env{mdbx_env};
        auto txn = db::RWTxnManaged{unmanaged_env};
        const auto db_path{unmanaged_env.get_path()};

        db::Buffer state_buffer{txn};
        state_buffer.set_memory_limit(batch_size);

        BoundedBuffer<std::optional<Block>> block_buffer{kMaxBlockBufferSize};
        [[maybe_unused]] auto _ = gsl::finally([&block_buffer] { block_buffer.terminate_and_release_all(); });
        BlockProvider block_provider{&block_buffer, unmanaged_env, start_block, max_block};
        boost::strict_scoped_thread<boost::interrupt_and_join_if_joinable> block_provider_thread(block_provider);

        const size_t max_batch_size{batch_size};
        auto signal_check_time{std::chrono::steady_clock::now()};

        std::optional<Block> block;
        BlockNum block_number{start_block};
        BlockNum last_block_number = 0;
        BlockExecutor block_executor{*chain_info, write_receipts, write_call_traces, write_change_sets, max_batch_size};
        ValidationResult last_exec_result = ValidationResult::kOk;

        while (block_number <= max_block) {
            while (block_number <= max_block) {
                block_buffer.pop_back(&block);
                if (!block) {
                    return SILKWORM_BLOCK_NOT_FOUND;
                }
                SILKWORM_ASSERT(block->header.number == block_number);

                try {
                    last_exec_result = block_executor.execute_single(*block, state_buffer);
                } catch (const db::Buffer::MemoryLimitError&) {
                    // batch done
                    break;
                }
                if (last_exec_result != ValidationResult::kOk) {
                    // firstly, persist the work done so far, then return SILKWORM_INVALID_BLOCK
                    break;
                }

                if (signal_check(signal_check_time)) {
                    return SILKWORM_TERMINATION_SIGNAL;
                }

                last_block_number = block_number;
                ++block_number;
            }

            StopWatch sw{/*auto_start=*/true};
            log::Info{"[4/12 Execution] Flushing state",  // NOLINT(*-unused-raii)
                      log_args_for_exec_flush(state_buffer, max_batch_size, last_block_number)};
            state_buffer.write_state_to_db();
            // Always save the Execution stage progress when state batch is flushed
            db::stages::write_stage_progress(txn, db::stages::kExecutionKey, last_block_number);
            // Commit and renew only in case of internally managed transaction
            txn.commit_and_renew();
            const auto elapsed_time_and_duration = sw.stop();
            log::Info("[4/12 Execution] Commit state+history",  // NOLINT(*-unused-raii)
                      log_args_for_exec_commit(elapsed_time_and_duration.second, db_path));

            if (last_executed_block) {
                *last_executed_block = last_block_number;
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

SILKWORM_EXPORT int silkworm_fini(SilkwormHandle handle) SILKWORM_NOEXCEPT {
    if (!handle) {
        return SILKWORM_INVALID_HANDLE;
    }
    if (!handle->snapshot_repository) {
        return SILKWORM_INVALID_HANDLE;
    }
    delete handle;

    is_initialized = false;

    return SILKWORM_OK;
}
